#include "ServerInterface.hpp"
#include <fstream>
#include <filesystem>
#include <vector>
#include <sstream>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

MealaServerInterface::MealaServerInterface(const Settings& settings, const MealaCredentials& creds)
    : ServerInterface(settings), _creds(creds)
{}

bool MealaServerInterface::login()
{
    std::string username, password, token;

    if (!_creds.credentials_file.empty() && fs::exists(_creds.credentials_file)) {
        std::ifstream f(_creds.credentials_file);
        json creds_json;
        f >> creds_json;
        username = creds_json.value("username", "");
        token = creds_json.value("token", "");
    } else {
        username = _creds.username;
        password = _creds.password;
    }

    httplib::Params params;
    params.emplace("username", username);
    if (!token.empty()) {
        params.emplace("token", token);
    } else {
        params.emplace("password", password);
    }

    std::string url_path = "/login";
    httplib::Result res;
    if (_protocol == Protocol::Https) {
        httplib::SSLClient cli(_settings.server_url);
        res = cli.Post(url_path.c_str(), params);
    } else {
        httplib::Client cli(_settings.server_url);
        res = cli.Post(url_path.c_str(), params);
    }

    if (res && res->status == 200) {
        auto it = res->headers.find("Set-Cookie");
        if (it != res->headers.end()) {
            _session_cookie = it->second;
            _logged_in = true;
            return true;
        }
    }
    _logged_in = false;
    return false;
}

ServerInterface::UploadResult MealaServerInterface::upload_log(const std::string& file_path)
{
    if (!_logged_in && !login()) {
        return {false, 401, "Login to Meala failed"};
    }

    constexpr size_t chunk_size = 5 * 1024 * 1024; // 5 MB

    if (!fs::exists(file_path)) {
        return {false, 404, "Log file does not exist: " + file_path};
    }
    size_t file_size = fs::file_size(file_path);
    size_t total_chunks = (file_size / chunk_size) + (file_size % chunk_size ? 1 : 0);
    std::string filename = fs::path(file_path).filename().string();

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return {false, 0, "Failed to open file"};
    }

    for (size_t chunk_index = 0; chunk_index < total_chunks; ++chunk_index) {
        size_t offset = chunk_index * chunk_size;
        size_t this_chunk_size = std::min(chunk_size, file_size - offset);
        std::vector<char> buffer(this_chunk_size);
        file.read(buffer.data(), this_chunk_size);

        httplib::MultipartFormDataItems items = {
            {"comments", "Log uploaded from C++ API", "", ""},
            {"battery", "", "", ""},
            {"pic", "", "", ""},
            {"gso", "", "", ""},
            {"vehicle_id", "", "", ""},
            {"dzchunkbyteoffset", std::to_string(offset), "", ""},
            {"dzchunkindex", std::to_string(chunk_index), "", ""},
            {"dztotalchunkcount", std::to_string(total_chunks), "", ""},
            {"files", std::string(buffer.begin(), buffer.end()), filename, "application/octet-stream"}
        };

        std::string url_path = "/upload/api";
        httplib::Headers headers;
        if (!_session_cookie.empty()) {
            headers.emplace("Cookie", _session_cookie);
        }

        httplib::Result res;
        if (_protocol == Protocol::Https) {
            httplib::SSLClient cli(_settings.server_url);
            res = cli.Post(url_path.c_str(), headers, items);
        } else {
            httplib::Client cli(_settings.server_url);
            res = cli.Post(url_path.c_str(), headers, items);
        }

        if (!res || res->status != 200) {
            std::ostringstream oss;
            oss << "Upload failed on chunk " << (chunk_index + 1) << ": "
                << (res ? std::to_string(res->status) : "No response");
            return {false, res ? res->status : 0, oss.str()};
        }
    }

    return {true, 200, "Upload completed successfully."};
}
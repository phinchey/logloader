#include "MealaUploadTarget.hpp"
#include "Log.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>

// CPPHTTPLIB_OPENSSL_SUPPORT is set for the whole target in CMakeLists.txt;
// see the note in UploadTarget.cpp for why it is not defined per-file.
#include <httplib.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

MealaUploadTarget::MealaUploadTarget(const UploadTargetConfig& config)
	: UploadTarget(config)
{}

std::optional<UploadTarget::Result> MealaUploadTarget::load_credentials()
{
	std::error_code ec;

	if (!fs::exists(_config.credentials_file, ec)) {
		return Result{Outcome::Unauthorized, 0, "credentials file is missing: " + _config.credentials_file, ""};
	}

	std::ifstream file(_config.credentials_file);

	if (!file) {
		return Result{Outcome::Unauthorized, 0, "cannot open credentials file: " + _config.credentials_file, ""};
	}

	MealaCredentials credentials;

	try {
		const nlohmann::json parsed = nlohmann::json::parse(file);
		credentials.username = parsed.value("username", "");
		credentials.token = parsed.value("token", "");

	} catch (const nlohmann::json::exception& error) {
		// A truncated or hand-edited file is a stable failure, not a transient
		// one: it stays broken until somebody replaces it.
		return Result{Outcome::Unauthorized, 0, std::string("cannot parse credentials file: ") + error.what(), ""};
	}

	if (credentials.username.empty() || credentials.token.empty()) {
		return Result{Outcome::Unauthorized, 0, "credentials file has no username/token pair: " + _config.credentials_file, ""};
	}

	_credentials = std::move(credentials);
	return std::nullopt;
}

std::optional<UploadTarget::Result> MealaUploadTarget::login()
{
	if (_logged_in) {
		return std::nullopt;
	}

	if (const auto problem = load_credentials(); problem.has_value()) {
		note_unauthorized();
		return problem;
	}

	httplib::Params params;
	params.emplace("username", _credentials.username);
	params.emplace("token", _credentials.token);

	httplib::Client client(_config.url);
	client.set_connection_timeout(30, 0);
	client.set_read_timeout(30, 0);

	const httplib::Result response = client.Post("/login", params);

	if (!response) {
		return Result{Outcome::Unreachable, 0, "connection failed during login", ""};
	}

	if (response->status != 200) {
		note_unauthorized();
		return Result{Outcome::Unauthorized, response->status, "login was refused", ""};
	}

	// The session cookie is the only thing that makes the upload calls
	// authenticated; a 200 without one would upload as nobody.
	if (!response->has_header("Set-Cookie")) {
		note_unauthorized();
		return Result{Outcome::Unauthorized, response->status, "login returned no session cookie", ""};
	}

	_session_cookie = response->get_header_value("Set-Cookie");
	_logged_in = true;
	return std::nullopt;
}

UploadTarget::Result MealaUploadTarget::upload(const std::string& file_path)
{
	// Same reasoning as the base class: a rejected account stays rejected, and
	// re-posting a whole log to find that out again helps nobody.
	if (in_unauthorized_cooldown()) {
		return {Outcome::Unreachable, 0, "waiting out an unauthorized response", ""};
	}

	size_t size = 0;

	if (const auto problem = check_local_file(file_path, size); problem.has_value()) {
		return *problem;
	}

	if (!reachable()) {
		return {Outcome::Unreachable, 0, "server unreachable", ""};
	}

	if (const auto problem = login(); problem.has_value()) {
		return *problem;
	}

	std::ifstream file(file_path, std::ios::binary);

	if (!file) {
		return {Outcome::Missing, 0, "cannot open local file: " + file_path, ""};
	}

	const std::string name = fs::path(file_path).filename().string();
	const size_t total_chunks = (size + kChunkSize - 1) / kChunkSize;

	LOG("Uploading " << name << " to " << _config.name << " (" << _config.url << ") in "
	    << total_chunks << (total_chunks == 1 ? " chunk" : " chunks"));

	httplib::Client client(_config.url);
	client.set_connection_timeout(30, 0);
	client.set_read_timeout(300, 0);
	client.set_write_timeout(300, 0);
	client.set_follow_location(false);

	httplib::Headers headers;
	headers.emplace("Cookie", _session_cookie);

	std::vector<char> buffer;

	for (size_t index = 0; index < total_chunks; index++) {
		const size_t offset = index * kChunkSize;
		const size_t length = std::min(kChunkSize, size - offset);

		buffer.resize(length);

		if (!file.read(buffer.data(), static_cast<std::streamsize>(length))) {
			// The file shrank or went away mid-upload; fetching it again is the
			// way out, which is what Missing asks the caller to do.
			return {Outcome::Missing, 0, "local file ended early: " + file_path, ""};
		}

		// Meala reads every one of these off the form. The ones an automated
		// upload has nothing to say about still have to be present.
		const httplib::MultipartFormDataItems fields = {
			{"comments", "Uploaded by logloader", "", ""},
			{"battery", "", "", ""},
			{"pic", "", "", ""},
			{"gso", "", "", ""},
			{"vehicle_id", "", "", ""},
			{"dzchunkbyteoffset", std::to_string(offset), "", ""},
			{"dzchunkindex", std::to_string(index), "", ""},
			{"dztotalchunkcount", std::to_string(total_chunks), "", ""},
			{"files", std::string(buffer.begin(), buffer.end()), name, "application/octet-stream"},
		};

		const httplib::Result response = client.Post("/upload/api", headers, fields);

		if (!response) {
			return {Outcome::Retry, 0, "connection failed during upload", ""};
		}

		const int status = response->status;

		if (status == 200 || status == 201) {
			continue;
		}

		if (status == 401 || status == 403) {
			// The session expired mid-upload, or the account lost its access.
			// Either way the next attempt logs in again from the top.
			_logged_in = false;
			_session_cookie.clear();
			note_unauthorized();
			return {Outcome::Unauthorized, status, "not authorized", ""};
		}

		if (status == 400) {
			return {Outcome::Rejected, status, "rejected by the server", ""};
		}

		return {Outcome::Retry, status, "server error on chunk " + std::to_string(index + 1)
			+ "/" + std::to_string(total_chunks), ""};
	}

	// Meala's upload API answers per chunk and hands back no per-log url, so
	// there is no location to record the way Flight Review's redirect gives one.
	return {Outcome::Success, 200, "uploaded", ""};
}

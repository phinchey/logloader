#pragma once

#include <string>
#include <vector>
#include <sqlite3.h>
#include <mavsdk/plugins/log_files/log_files.h>
#include <optional>

enum class UploadService {
	FlightReview = 0,
	Meala = 1
};

class ServerInterface
{
public:
	struct Settings {
		std::string server_url;
		std::string user_email;
		std::string logs_directory;
		std::string db_path;         // Path to this server's database
		bool upload_enabled {};
		bool public_logs {};
		UploadService upload_service;
		std::string credentials_file; // For Meala credentials
	};

	struct UploadResult {
		bool success;
		int status_code;    // HTTP status code, or 0 if not applicable
		std::string message;
	};

	struct DatabaseEntry {
		std::string uuid;
		uint32_t id;
		std::string date;
		uint32_t size_bytes;
		bool downloaded;
	};

	ServerInterface(const Settings& settings);
	~ServerInterface();

	// Database initialization
	bool init_database();
	void close_database();

	// Log entry management
	static std::string generate_uuid(const mavsdk::LogFiles::Entry& entry);
	bool add_log_entry(const mavsdk::LogFiles::Entry& entry);
	bool update_download_status(const std::string& uuid, bool downloaded);
	uint32_t num_logs_to_download();

	// Upload management
	uint32_t num_logs_to_upload();
	DatabaseEntry get_next_log_to_upload();
	UploadResult upload_log(const std::string& filepath);

	// Query methods
	bool is_blacklisted(const std::string& uuid);
	DatabaseEntry get_next_log_to_download();

	std::string filepath_from_entry(const mavsdk::LogFiles::Entry& entry) const ;
	std::string filepath_from_uuid(const std::string& uuid) const;

	void start();
	void stop();

protected:
	enum class Protocol {
		Http,
		Https
	};
	virtual UploadResult upload(const std::string& filepath);
	Protocol _protocol {Protocol::Https};
	Settings _settings;

private:
	void sanitize_url_and_determine_protocol();
	bool server_reachable();

	// Database operations
	bool execute_query(const std::string& query);
	bool add_to_blacklist(const std::string& uuid, const std::string& reason);
	DatabaseEntry row_to_db_entry(sqlite3_stmt* stmt);

	bool _should_exit = false;
	sqlite3* _db = nullptr;
};

struct MealaCredentials {
	std::string username;
	std::string password;
	std::string token;
	std::string credentials_file;
};

class MealaServerInterface : public ServerInterface
{
public:
	MealaServerInterface(const Settings& settings, const MealaCredentials& creds);

	bool login();
	UploadResult upload(const std::string& filepath) override;

private:
	MealaCredentials _creds;
	std::string _session_cookie;
	bool _logged_in = false;
};
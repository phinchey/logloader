#pragma once

#include <optional>
#include <string>

#include "UploadTarget.hpp"

namespace httplib
{
class Client;
}

// One Meala account, as read from the JSON credentials file the Meala account
// page hands out:
//
//     {"username": "...", "token": "..."}
//
// Meala has no anonymous upload, so a target without these cannot upload at
// all; Config rejects one that is enabled without a credentials_file.
struct MealaCredentials {
	std::string username;
	std::string token;
};

// Uploads to Meala instead of Flight Review. Two things differ from the base
// class: every request carries a session cookie obtained from /login, and the
// log goes up in fixed-size chunks rather than as one streamed body, because
// /upload/api takes the Dropzone-style chunk fields.
class MealaUploadTarget : public UploadTarget
{
public:
	explicit MealaUploadTarget(const UploadTargetConfig& config);

	Result upload(const std::string& file_path) override;

private:
	// POSTs /login and keeps the session cookie. Returns an unset optional once
	// there is a usable session, and the failure to report otherwise.
	std::optional<Result> login();

	// Read on the first login rather than at construction, so a credentials file
	// that appears after logloader started is picked up on the next attempt.
	std::optional<Result> load_credentials();

	// Confirms the session the login handed back is actually authenticated; see
	// the comment on the definition for why a 200 from /login is not enough.
	std::optional<Result> verify_session(httplib::Client& client);

	MealaCredentials _credentials;
	std::string _session_cookie;
	bool _logged_in {false};

	// What /upload/api expects per part. The whole log is never held in memory;
	// one chunk at a time is.
	static constexpr size_t kChunkSize = 5 * 1024 * 1024;
};

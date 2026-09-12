#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include "Config.hpp"

// One upload endpoint. Knows how to reach it and how to post a log to it; it
// holds no record of which logs exist or what has been uploaded, which is what
// LogDatabase is for.
//
// This class speaks Flight Review's upload API, which is the default and the
// only one that needs no account. Another backend subclasses it and overrides
// upload(); make_upload_target() builds the one the config asks for.
class UploadTarget
{
public:
	enum class Outcome {
		Success,
		// The local copy is gone or empty. Nothing is wrong with the log itself,
		// so the caller should fetch it again rather than give up on it.
		Missing,
		// The server will not take this log however often it is asked.
		Rejected,
		// The account is not authorized (yet). The log is fine; every other
		// upload to this target would fail the same way, so stop the batch and
		// keep the log queued.
		Unauthorized,
		// Could not connect. Stop the batch and try again after the cooldown.
		Unreachable,
		// Anything else: worth another attempt later.
		Retry,
	};

	struct Result {
		Outcome outcome {Outcome::Retry};
		int status_code {0};
		std::string message;
		// Path the server redirected to, e.g. "/plot_app?log=<uuid>".
		std::string location;
	};

	explicit UploadTarget(const UploadTargetConfig& config);
	virtual ~UploadTarget() = default;

	UploadTarget(const UploadTarget&) = delete;
	UploadTarget& operator=(const UploadTarget&) = delete;

	const std::string& name() const { return _config.name; }
	const std::string& url() const { return _config.url; }
	bool enabled() const { return _config.enabled; }

	virtual Result upload(const std::string& file_path);

protected:
	// Probes at most once per cooldown and logs only on the down/up
	// transitions, so a server that is simply off does not produce one failure
	// line per pending log.
	bool reachable();

	// A subclass reports a 401/403 through these so every backend gets the same
	// cooldown; see kUnauthorizedCooldown.
	void note_unauthorized();
	bool in_unauthorized_cooldown() const;

	// Common to every backend: the local file has to exist and have something in
	// it before any of them is worth opening a socket for. Returns an unset
	// optional when the file is fit to upload.
	std::optional<Result> check_local_file(const std::string& file_path, size_t& size) const;

	UploadTargetConfig _config;

private:
	static constexpr auto kUnreachableCooldown = std::chrono::seconds(60);
	std::chrono::steady_clock::time_point _unreachable_until {};
	bool _reported_unreachable {false};

	// 401/403 is a stable state -- the account stays unauthorized until a human
	// does something -- and each attempt posts the whole log just to be told no
	// again, so it gets a much longer cooldown than a connection failure.
	static constexpr auto kUnauthorizedCooldown = std::chrono::minutes(5);
	std::chrono::steady_clock::time_point _unauthorized_until {};
};

// Builds the target config.backend asks for.
std::unique_ptr<UploadTarget> make_upload_target(const UploadTargetConfig& config);

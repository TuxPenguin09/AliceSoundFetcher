#pragma once

#include <filesystem>
#include "AFAFormat.h"

namespace fs = std::filesystem;

class AFARead {
public:
	static AFAArchive parse(const fs::path& afaPath);
};
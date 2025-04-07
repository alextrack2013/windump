#include <fstream>
#include <sstream>
#include <string>

namespace JSON {
    std::string EscapeString(const std::string& input);
    std::string WideToJsonString(const wchar_t* wideStr);
    void AddIndent(std::ostringstream& json);
    void StartObject(std::ostringstream& json, const std::string& key = "");
    void EndObject(std::ostringstream& json);

    void AddKeyValue(std::ostringstream& json, const std::string& key, const std::string& value, bool last = false);
    void AddKeyValue(std::ostringstream& json, const std::string& key, int value, bool last = false);
    void AddKeyValue(std::ostringstream& json, const std::string& key, unsigned long value, bool last = false);
    void AddKeyValue(std::ostringstream& json, const std::string& key, __int64 value, bool last = false);
    void AddKeyValue(std::ostringstream& json, const std::string& key, float value, bool last = false);
    void AddKeyValue(std::ostringstream& json, const std::string& key, bool value, bool last = false);

    void SaveToFile(const std::string& filename, std::ostringstream& json);
}

void CollectKUSD(std::ostringstream& json);
void CollectPEB(std::ostringstream& json);
void CollectCPUID(std::ostringstream& json);
void CollectXGETBV(std::ostringstream& json);
void CollectSystemInfo(std::ostringstream& json);
void CollectWindowsInfo(std::ostringstream& json);

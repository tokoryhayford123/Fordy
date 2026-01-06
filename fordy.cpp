#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <openssl/md5.h>  // For MD5; assume OpenSSL is installed
#include <openssl/sha.h>  // For SHA-1 and SHA-256

// Simple hash utility functions (wrappers for OpenSSL)
std::string computeMD5(const std::string& input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, input.c_str(), input.size());
    MD5_Final(hash, &md5);
    char mdString[33];
    for(int i = 0; i < 16; i++) sprintf(mdString + (i*2), "%02x", (unsigned char)hash[i]);
    return std::string(mdString);
}

std::string computeSHA1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, input.c_str(), input.size());
    SHA1_Final(hash, &sha1);
    char shaString[41];
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++) sprintf(shaString + (i*2), "%02x", (unsigned char)hash[i]);
    return std::string(shaString);
}

std::string computeSHA256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    char shaString[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(shaString + (i*2), "%02x", (unsigned char)hash[i]);
    return std::string(shaString);
}

// Global mutex for thread-safe logging
std::mutex logMutex;

// Function to perform dictionary attack
void dictionaryAttack(const std::vector<std::string>& hashes, const std::vector<std::string>& dictionary, const std::string& hashType, std::vector<std::pair<std::string, std::string>>& results, int maxAttempts) {
    int attempts = 0;
    for (const auto& word : dictionary) {
        if (attempts >= maxAttempts) break;
        std::string hashedWord;
        if (hashType == "MD5") hashedWord = computeMD5(word);
        else if (hashType == "SHA1") hashedWord = computeSHA1(word);
        else if (hashType == "SHA256") hashedWord = computeSHA256(word);
        else continue;  // Unsupported hash

        for (const auto& hash : hashes) {
            if (hashedWord == hash) {
                std::lock_guard<std::mutex> lock(logMutex);
                results.push_back({hash, word});  // Store cracked hash and password
                std::cout << "Cracked: Hash " << hash << " with password: " << word << std::endl;
            }
            attempts++;
            if (attempts >= maxAttempts) break;
        }
    }
}

// Function to perform brute force attack
void bruteForceAttack(const std::vector<std::string>& hashes, const std::string& hashType, std::vector<std::pair<std::string, std::string>>& results, int length, const std::string& charset, int maxAttempts) {
    int attempts = 0;
    std::string attempt(length, ' ');
    while (true) {
        if (attempts >= maxAttempts) break;
        for (size_t i = 0; i < attempt.size(); ++i) attempt[i] = charset[0];  // Reset

        while (true) {
            std::string hashedAttempt;
            if (hashType == "MD5") hashedAttempt = computeMD5(attempt);
            else if (hashType == "SHA1") hashedAttempt = computeSHA1(attempt);
            else if (hashType == "SHA256") hashedAttempt = computeSHA256(attempt);
            else break;

            for (const auto& hash : hashes) {
                if (hashedAttempt == hash) {
                    std::lock_guard<std::mutex> lock(logMutex);
                    results.push_back({hash, attempt});
                    std::cout << "Cracked: Hash " << hash << " with password: " << attempt << std::endl;
                }
                attempts++;
                if (attempts >= maxAttempts) return;
            }

            // Increment the string
            int i = attempt.size() - 1;
            while (i >= 0) {
                size_t charIdx = charset.find(attempt[i]);
                if (charIdx == std::string::npos || charIdx + 1 >= charset.size()) {
                    attempt[i] = charset[0];
                    i--;
                } else {
                    attempt[i] = charset[charIdx + 1];
                    break;
                }
            }
            if (i < 0) break;  // Exhausted all combinations
        }
    }
}

// Function to apply rules to dictionary words (e.g., capitalize, append numbers)
std::vector<std::string> applyRules(const std::vector<std::string>& dictionary) {
    std::vector<std::string> modified;
    for (const auto& word : dictionary) {
        modified.push_back(word);  // Original
        modified.push_back(word + "1");  // Append number
        modified.push_back(word + "!");
        std::string upperWord = word;
        for (char& c : upperWord) c = toupper(c);
        modified.push_back(upperWord);
        // Add more rules as needed
    }
    return modified;
}

int main() {
    std::string hashFile = "hashes.txt";  // File containing hashes, one per line
    std::string dictFile = "dictionary.txt";  // File containing dictionary words
    std::string hashType = "SHA256";  // User-specified hash type
    int maxAttempts = 1000000;  // Safety limit
    int numThreads = 4;  // Number of threads for parallel processing

    // Read hashes from file
    std::vector<std::string> hashes;
    std::ifstream hashIn(hashFile);
    std::string line;
    while (std::getline(hashIn, line)) hashes.push_back(line);

    // Read dictionary
    std::vector<std::string> dictionary;
    std::ifstream dictIn(dictFile);
    while (std::getline(dictIn, line)) dictionary.push_back(line);

    std::vector<std::pair<std::string, std::string>> results;  // To store cracked results

    // Apply rules to dictionary
    auto ruledDictionary = applyRules(dictionary);

    // Launch threads for attacks
    std::vector<std::thread> threads;

    // Thread for dictionary attack
    threads.emplace_back(dictionaryAttack, std::ref(hashes), std::ref(ruledDictionary), hashType, std::ref(results), maxAttempts);

    // Thread for brute force (e.g., on 4-6 character passwords with alphanumeric charset)
    std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    threads.emplace_back(bruteForceAttack, std::ref(hashes), hashType, std::ref(results), 6, charset, maxAttempts / numThreads);

    for (auto& th : threads) th.join();

    // Generate report
    std::ofstream report("crack_report.txt");
    report << "Cracking Report:\n";
    report << "Hash Type: " << hashType << "\n";
    for (const auto& result : results) {
        report << "Cracked Hash: " << result.first << " with Password: " << result.second << "\n";
    }
    report << "Total Cracked: " << results.size() << "\n";
    report.close();

    std::cout << "Report generated in crack_report.txt" << std::endl;
    return 0;
}
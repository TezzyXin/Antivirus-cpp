#include <openssl/aes.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <iostream>


int hashedFiles, filesInQuarantine, scannedPaths = 0;

std::vector<std::string> hashFile(std::vector<std::string> paths) {
    std::vector<std::string> hashes;
    for (auto it = paths.begin(); it != paths.end(); ++it) {
        long index = distance(paths.begin(), it);
        auto *s = new std::string;
        s->reserve(1024);
        std::fstream fp;
        std::string filename = paths.at(index);
        //std::cout << filename << std::endl;
        fp.open(filename, std::ios::in);
        if (!(fp.is_open())) {
            std::cout << "\nUnable to open the file " << filename << std::endl;
            hashes.emplace_back(" ");
        } else {
            std::string line;
            while (fp >> line) {
                s->append(line);
            }
            fp.close();
            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, s->c_str(), s->size());
            SHA256_Final(digest.data(), &ctx);

            delete s;

            std::array<char, SHA256_DIGEST_LENGTH * 2 + 1> mdString{};
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                sprintf(&(mdString[i * 2]), "%02x", (unsigned int) digest[i]);
            }
            fprintf(stdout, "\nHash of the file \"%s\": \n%s\n", filename.c_str(), mdString.data());
            hashes.emplace_back(mdString.data());
            hashedFiles++;
        }
    }
    return hashes;
}

std::vector<std::string> scanFolder(int option) {
    std::vector<std::string> paths;
    if (option == 1) {
        std::cout << "Enter folder name: ";
        std::string folderPath;
        std::cin >> folderPath;
        try {
            for (const auto &file: std::filesystem::recursive_directory_iterator(folderPath,
                                                                                 std::filesystem::directory_options::skip_permission_denied)) {
                const std::filesystem::path &path(file.path());
                std::error_code ec;
                if (access(file.path().c_str(), R_OK) == 0) {
                    if (std::filesystem::is_regular_file(path, ec)) {
                        paths.push_back(file.path());
                    } else if (std::filesystem::is_directory(path, ec)) {
                        scannedPaths++;
                    }
                } else {
                    std::cout << file.path() << std::endl;
                    continue;
                }
            }
        } catch (...) {
            std::cout << "Directory does not exist!" << std::endl;
        }
    } else if (option == 2) {
        std::cout << "Enter file name: ";
        std::string filePath;
        std::cin >> filePath;
        try {
            const std::filesystem::path path(filePath);
            std::error_code ec;
            if (std::filesystem::exists(path)) {
                if (std::filesystem::is_regular_file(path, ec)) {
                    paths.push_back(filePath);
                    scannedPaths++;
                } else {
                    std::cout << "It is not a valid path!" << std::endl;
                }
            } else {
                std::cout << "File does not exist!" << std::endl;
            }
        }
        catch (...) {
            std::cout << "File does not exist!" << std::endl;
        }
    }
    return paths;
}

std::vector<std::string> readLines(const std::string &fileName) {
    std::vector<std::string> lines;
    std::ifstream input_file(fileName);
    if (!input_file.is_open()) {
        std::cerr << "Could not open the file " << fileName << std::endl;
    }
    for (std::string line; getline(input_file, line);) {
        lines.push_back(line);
    }
    return lines;
}


void writeToFile(const std::string &filename, const std::string &text) {
    std::ofstream fileOut;
    fileOut.open(filename, std::ios_base::app);
    fileOut << text << std::endl;
}

int readNumberOfLines() {
    std::string line;
    int number = 0;
    std::ifstream pathsFile("../quarantinedFiles/paths.txt");
    if (pathsFile.is_open()) {
        while (pathsFile.peek() != EOF) {
            getline(pathsFile, line);
            number++;
        }
        pathsFile.close();
    } else {
        std::cout << "Could not open the file" << std::endl;
    }
    return number;
}

void encrypt(const char *path) {
    int count = readNumberOfLines();
    std::string pathString = std::string(path);
    std::string filename = pathString.substr(pathString.find_last_of('/') + 1);
    std::string newPath = "../quarantinedFiles/quarantined" + std::to_string(count + 1);
    std::filesystem::rename(path, newPath);

    writeToFile("../quarantinedFiles/paths.txt", pathString);

    unsigned long bytes_read;

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

    unsigned char ckey[] = "firstkeyofcipher";
    unsigned char ivec[] = "aesisimplemented";

    AES_KEY key;

    AES_set_encrypt_key(ckey, 128, &key);

    int num = 0;
    FILE *ifp = fopen(newPath.c_str(), "rb");
    FILE *ofp = fopen("tempOutput", "wb");
    while (true) {
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

        AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, AES_ENCRYPT);

        fwrite(outdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }
    fclose(ifp);
    fclose(ofp);
    std::filesystem::rename("tempOutput", newPath.c_str());
    std::cout << "File has been encrypted and moved to directory: " << newPath << std::endl;
}

void decrypt(const char *path) {

    std::string pathString = std::string(path);
    std::string filename = pathString.substr(pathString.find_last_of('/') + 1);
    std::string numberOfLine = filename.substr(11);
    std::ifstream f("../quarantinedFiles/paths.txt");
    std::string oldFilename;
    for (int i = 1; i <= std::stoi(numberOfLine); i++) {
        std::getline(f, oldFilename);
    }
    std::filesystem::rename(path, oldFilename);

    unsigned long bytes_read;

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

    unsigned char ckey[] = "firstkeyofcipher";
    unsigned char ivec[] = "aesisimplemented";

    AES_KEY key;

    AES_set_encrypt_key(ckey, 128, &key);

    int num = 0;

    FILE *ifp = fopen(oldFilename.c_str(), "rb");
    FILE *ofp = fopen("tempOutput", "wb");

    while (true) {
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

        AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, AES_DECRYPT);

        fwrite(outdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }
    fclose(ifp);
    fclose(ofp);
    std::filesystem::rename("tempOutput", oldFilename.c_str());
    std::cout << "File has been decrypted and moved back to directory: " << oldFilename << std::endl;
}

void checkFileSafety(const std::string &path, const std::string &hash, const std::vector<std::string> &signatures) {
    for (const auto &element: signatures) {
        if (hash == element) {
            std::cout << "\nInfected file! " + path + "\n";
            encrypt(path.c_str());
            filesInQuarantine++;
        }
    }
}

void menu() {

    int choice = 0;

    do {
        std::cout << "\n\t1 - Hash files in specified folder\n";
        std::cout << "\t2 - Hash specified file\n";
        std::cout << "\t3 - Show statistics\n";
        std::cout << "\t4 - Decrypt file\n";
        std::cout << "\t5 - Update signature database\n";
        std::cout << "\t6 - Exit\n";
        std::cout << "\nChoose option: ";
        std::cin >> choice;
        std::cout << "\n";

        std::vector<std::string> signatures = readLines("../signatures.txt");

        switch (choice) {
            case 1: {
                std::vector<std::string> paths = scanFolder(1);
                std::vector<std::string> hashes = hashFile(paths);
                for (auto it = paths.begin(); it != paths.end(); ++it) {
                    long index = distance(paths.begin(), it);
                    checkFileSafety(paths.at(index), hashes.at(index), signatures);
                }
                break;
            }
            case 2: {
                std::vector<std::string> paths = scanFolder(2);
                if (paths.empty()) {
                    continue;
                } else {
                    std::string hash = hashFile(paths).front();
                    std::string path = paths.front();
                    checkFileSafety(path, hash, signatures);
                }
                break;
            }
            case 3: {
                std::cout << "Number of hashed files: " + std::to_string(hashedFiles) + "\n";
                std::cout << "Number of scanned paths: " + std::to_string(scannedPaths) + "\n";
                std::cout << "Number of files added to quarantine: " + std::to_string(filesInQuarantine) + "\n";
                break;
            }
            case 4: {
                std::string path;
                std::cout << "Enter file name: ";
                std::cin >> path;
                if (std::filesystem::exists(path) && path.substr(0, 20) == "../quarantinedFiles/") {
                    decrypt(path.c_str());
                } else {
                    std::cout << "File does not exist!" << std::endl;
                }
                break;
            }
            case 5: {
                std::cout << "Choose file which hash should be added to signature database" << std::endl;
                std::vector<std::string> paths = scanFolder(2);
                if (std::filesystem::exists(paths.front())) {
                    std::string hash = hashFile(paths).front();
                    bool status = false;
                    for (const auto &element: signatures) {
                        if (hash == element) {
                            std::cout << "This signature is already in the database!" << std::endl;
                            status = true;
                            break;
                        }
                    }
                    if (!status) {
                        writeToFile("../signatures.txt", hash);
                        std::cout << "Updated database with hash of file: " << paths.front() << std::endl;
                    }
                }
                break;
            }
            case 6:
                std::cout << "Quitting the program..." << std::endl;
                break;
            default: {
                std::cout << "Not a valid option! Quitting the program..." << std::endl;
                break;
            }
        }
    } while (choice == 1 || choice == 2 || choice == 3 || choice == 4 || choice == 5);
}


int main() {

    std::cout << "Simple antivirus by Jakub Romanek\n";

    menu();

    return 0;
}
#include <mime/mime.hpp>
#include <iostream>
#include <filesystem>

int main()
{
  std::filesystem::path p1 = "assets/app.js";
  std::filesystem::path p2 = "images/photo.jpeg";
  std::filesystem::path p3 = "file.bin";

  std::cout << p1 << " -> " << mime::from_path(p1) << "\n";
  std::cout << p2 << " -> " << mime::from_path(p2) << "\n";
  std::cout << p3 << " -> " << mime::from_path(p3) << "\n";

  return 0;
}

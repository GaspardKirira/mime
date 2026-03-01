#include <mime/mime.hpp>
#include <iostream>
#include <vector>
#include <cstdint>

int main()
{
  // Simulate PNG file header
  std::vector<std::uint8_t> png = {
      0x89, 0x50, 0x4E, 0x47,
      0x0D, 0x0A, 0x1A, 0x0A};

  std::cout << "Sniff PNG -> "
            << mime::sniff(png) << "\n";

  // Simulate PDF header
  std::vector<std::uint8_t> pdf = {
      0x25, 0x50, 0x44, 0x46, 0x2D};

  std::cout << "Sniff PDF -> "
            << mime::sniff(pdf) << "\n";

  return 0;
}

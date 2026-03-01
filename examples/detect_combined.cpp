#include <mime/mime.hpp>
#include <iostream>
#include <vector>
#include <cstdint>

int main()
{
  // Unknown extension but valid PNG signature
  std::vector<std::uint8_t> head = {
      0x89, 0x50, 0x4E, 0x47,
      0x0D, 0x0A, 0x1A, 0x0A};

  std::cout << "detect(.unknown, PNG-bytes) -> "
            << mime::detect(".unknown", head) << "\n";

  // Known extension wins over sniffing
  std::cout << "detect(.txt, PNG-bytes) -> "
            << mime::detect(".txt", head) << "\n";

  return 0;
}

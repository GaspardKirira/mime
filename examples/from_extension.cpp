#include <mime/mime.hpp>
#include <iostream>

int main()
{
  std::cout << "index.html -> "
            << mime::from_extension(".html") << "\n";

  std::cout << "image.PNG -> "
            << mime::from_extension("PNG") << "\n";

  std::cout << "archive.unknown -> "
            << mime::from_extension(".unknown") << "\n";

  return 0;
}

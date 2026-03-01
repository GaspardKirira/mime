#include <mime/mime.hpp>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

static void test_extension_mapping()
{
  assert(mime::from_extension(".png") == "image/png");
  assert(mime::from_extension("JPG") == "image/jpeg");
  assert(mime::from_extension("html").find("text/html") != std::string::npos);
  assert(mime::from_extension(".unknown") == "application/octet-stream");
}

static void test_sniff_png()
{
  const std::vector<std::uint8_t> head = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00};
  assert(mime::sniff(head) == "image/png");
}

static void test_sniff_jpeg()
{
  const std::vector<std::uint8_t> head = {0xFF, 0xD8, 0xFF, 0xE0, 0x00};
  assert(mime::sniff(head) == "image/jpeg");
}

static void test_sniff_pdf()
{
  const std::vector<std::uint8_t> head = {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31};
  assert(mime::sniff(head) == "application/pdf");
}

static void test_sniff_zip()
{
  const std::vector<std::uint8_t> head = {0x50, 0x4B, 0x03, 0x04, 0x14};
  assert(mime::sniff(head) == "application/zip");
}

static void test_sniff_mp4()
{
  // minimal MP4-like header: 00 00 00 18 'f' 't' 'y' 'p' ...
  const std::vector<std::uint8_t> head = {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D};
  assert(mime::sniff(head) == "video/mp4");
}

static void test_detect_prefers_extension()
{
  // Even if bytes look like PNG, extension should win.
  const std::vector<std::uint8_t> head = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
  const std::string out = mime::detect(".txt", head);
  assert(out.find("text/plain") != std::string::npos);
}

static void test_detect_falls_back_to_sniff()
{
  const std::vector<std::uint8_t> head = {0x25, 0x50, 0x44, 0x46, 0x2D};
  assert(mime::detect(".unknown", head) == "application/pdf");
}

int main()
{
  test_extension_mapping();
  test_sniff_png();
  test_sniff_jpeg();
  test_sniff_pdf();
  test_sniff_zip();
  test_sniff_mp4();
  test_detect_prefers_extension();
  test_detect_falls_back_to_sniff();
  return 0;
}

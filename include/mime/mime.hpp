/**
 * @file mime.hpp
 * @brief MIME type detection and mapping by extension plus sniffing helpers.
 *
 * `mime` provides deterministic MIME utilities for common web/file workflows:
 * - map file extensions to MIME types (case-insensitive)
 * - infer a MIME type from a filesystem path
 * - basic content sniffing for a few common formats (PNG/JPEG/GIF/PDF/ZIP/MP3/MP4)
 *
 * Header-only. Zero external dependencies.
 *
 * Requirements: C++17+
 */

#ifndef MIME_MIME_HPP
#define MIME_MIME_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mime
{
  namespace fs = std::filesystem;

  /**
   * @brief Lowercase ASCII string (for case-insensitive extension matching).
   */
  namespace detail
  {
    inline char ascii_lower(char c) noexcept
    {
      if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
      return c;
    }

    inline std::string lower_ascii(std::string_view s)
    {
      std::string out;
      out.reserve(s.size());
      for (char c : s)
      {
        out.push_back(ascii_lower(c));
      }
      return out;
    }

    inline bool starts_with_bytes(const std::vector<std::uint8_t> &buf,
                                  std::initializer_list<std::uint8_t> sig) noexcept
    {
      if (buf.size() < sig.size())
        return false;

      std::size_t i = 0;
      for (auto b : sig)
      {
        if (buf[i] != b)
          return false;
        ++i;
      }
      return true;
    }

    inline bool match_bytes_at(const std::vector<std::uint8_t> &buf,
                               std::size_t offset,
                               std::initializer_list<std::uint8_t> sig) noexcept
    {
      if (offset + sig.size() > buf.size())
        return false;

      std::size_t i = 0;
      for (auto b : sig)
      {
        if (buf[offset + i] != b)
          return false;
        ++i;
      }
      return true;
    }

    inline std::string normalize_ext(std::string_view ext)
    {
      // ext can be ".png" or "png". Store as "png".
      if (!ext.empty() && ext.front() == '.')
        ext.remove_prefix(1);

      return lower_ascii(ext);
    }
  } // namespace detail

  /**
   * @brief Return the default MIME type mapping table (extension -> MIME type).
   *
   * Keys are stored without dot, lowercased: "png", "html", "json", ...
   */
  inline const std::unordered_map<std::string, std::string> &default_map()
  {
    static const std::unordered_map<std::string, std::string> kMap = {
        // text
        {"txt", "text/plain; charset=utf-8"},
        {"text", "text/plain; charset=utf-8"},
        {"csv", "text/csv; charset=utf-8"},
        {"html", "text/html; charset=utf-8"},
        {"htm", "text/html; charset=utf-8"},
        {"css", "text/css; charset=utf-8"},
        {"js", "text/javascript; charset=utf-8"},
        {"mjs", "text/javascript; charset=utf-8"},
        {"json", "application/json"},
        {"xml", "application/xml"},
        {"md", "text/markdown; charset=utf-8"},

        // images
        {"png", "image/png"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"gif", "image/gif"},
        {"webp", "image/webp"},
        {"svg", "image/svg+xml"},
        {"ico", "image/x-icon"},

        // fonts
        {"woff", "font/woff"},
        {"woff2", "font/woff2"},
        {"ttf", "font/ttf"},
        {"otf", "font/otf"},

        // archives / binary
        {"zip", "application/zip"},
        {"gz", "application/gzip"},
        {"tgz", "application/gzip"},
        {"tar", "application/x-tar"},
        {"7z", "application/x-7z-compressed"},
        {"pdf", "application/pdf"},

        // audio/video
        {"mp3", "audio/mpeg"},
        {"wav", "audio/wav"},
        {"ogg", "audio/ogg"},
        {"mp4", "video/mp4"},
        {"webm", "video/webm"},

        // misc
        {"wasm", "application/wasm"},
        {"bin", "application/octet-stream"}};

    return kMap;
  }

  /**
   * @brief Lookup MIME type by file extension.
   *
   * @param ext File extension, with or without the leading dot. Case-insensitive.
   * @param fallback Fallback MIME type if unknown.
   */
  inline std::string from_extension(std::string_view ext,
                                    std::string_view fallback = "application/octet-stream")
  {
    const std::string key = detail::normalize_ext(ext);
    if (key.empty())
      return std::string(fallback);

    const auto &m = default_map();
    const auto it = m.find(key);
    if (it == m.end())
      return std::string(fallback);

    return it->second;
  }

  /**
   * @brief Lookup MIME type from a filesystem path.
   *
   * Uses the file extension only.
   */
  inline std::string from_path(const fs::path &p,
                               std::string_view fallback = "application/octet-stream")
  {
    return from_extension(p.extension().string(), fallback);
  }

  /**
   * @brief Basic content sniffing for a small set of common formats.
   *
   * This function is intentionally conservative.
   * It detects only a few formats with strong signatures.
   *
   * @param head First bytes of the file (recommend 64-4096 bytes).
   * @param fallback Fallback MIME type if unknown.
   */
  inline std::string sniff(const std::vector<std::uint8_t> &head,
                           std::string_view fallback = "application/octet-stream")
  {
    if (head.empty())
      return std::string(fallback);

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (detail::starts_with_bytes(head, {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}))
      return "image/png";

    // JPEG: FF D8 FF
    if (detail::starts_with_bytes(head, {0xFF, 0xD8, 0xFF}))
      return "image/jpeg";

    // GIF: "GIF87a" or "GIF89a"
    if (detail::starts_with_bytes(head, {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}) ||
        detail::starts_with_bytes(head, {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}))
      return "image/gif";

    // PDF: "%PDF-"
    if (detail::starts_with_bytes(head, {0x25, 0x50, 0x44, 0x46, 0x2D}))
      return "application/pdf";

    // ZIP: "PK\x03\x04" or "PK\x05\x06" or "PK\x07\x08"
    if (detail::starts_with_bytes(head, {0x50, 0x4B, 0x03, 0x04}) ||
        detail::starts_with_bytes(head, {0x50, 0x4B, 0x05, 0x06}) ||
        detail::starts_with_bytes(head, {0x50, 0x4B, 0x07, 0x08}))
      return "application/zip";

    // MP3: "ID3" tag
    if (detail::starts_with_bytes(head, {0x49, 0x44, 0x33}))
      return "audio/mpeg";

    // MP4: 'ftyp' at offset 4
    if (detail::match_bytes_at(head, 4, {0x66, 0x74, 0x79, 0x70}))
      return "video/mp4";

    // WebM: EBML header 1A 45 DF A3
    if (detail::starts_with_bytes(head, {0x1A, 0x45, 0xDF, 0xA3}))
      return "video/webm";

    return std::string(fallback);
  }

  /**
   * @brief Detect MIME type using extension first, then (optionally) sniffing bytes.
   *
   * If the extension is unknown, sniffing is used. If sniffing fails, fallback is returned.
   */
  inline std::string detect(std::string_view ext,
                            const std::vector<std::uint8_t> &head,
                            std::string_view fallback = "application/octet-stream")
  {
    const std::string by_ext = from_extension(ext, "");
    if (!by_ext.empty())
      return by_ext;

    return sniff(head, fallback);
  }

} // namespace mime

#endif // MIME_MIME_HPP

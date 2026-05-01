function FindProxyForURL(url, host) {
  // YouTube + Google video CDN
  if (shExpMatch(host, "*.youtube.com") ||
      shExpMatch(host, "youtube.com") ||
      shExpMatch(host, "*.googlevideo.com") ||
      shExpMatch(host, "*.ytimg.com") ||
      shExpMatch(host, "*.youtube-nocookie.com") ||
      shExpMatch(host, "youtube-nocookie.com") ||
      shExpMatch(host, "*.ggpht.com") ||
      shExpMatch(host, "*.googleapis.com") ||
      // Reddit
      shExpMatch(host, "*.reddit.com") ||
      shExpMatch(host, "reddit.com") ||
      shExpMatch(host, "*.redd.it") ||
      shExpMatch(host, "*.redditstatic.com") ||
      // Hulu
      shExpMatch(host, "*.hulu.com") ||
      shExpMatch(host, "hulu.com") ||
      shExpMatch(host, "*.hulustream.com") ||
      shExpMatch(host, "*.huluim.com") ||
      // Netflix
      shExpMatch(host, "*.netflix.com") ||
      shExpMatch(host, "netflix.com") ||
      shExpMatch(host, "*.nflxvideo.net") ||
      shExpMatch(host, "*.nflximg.net") ||
      shExpMatch(host, "*.nflxso.net") ||
      shExpMatch(host, "*.nflxext.com"))
    return "SOCKS5 127.0.0.1:1080";
  return "DIRECT";
}

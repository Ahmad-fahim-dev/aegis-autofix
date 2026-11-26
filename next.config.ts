import type { NextConfig } from "next";

// Security hardening (audit run-2): baseline security headers on every response.
// Deliberately NOT set: X-Frame-Options/frame-ancestors (the preview panel embeds
// the app cross-origin) and a full CSP (dev-server inline scripts would require
// nonce plumbing) — both are noted as residual hardening for a production deploy.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  // The console is fronted by the sandbox gateway (Caddy on :81) and the preview
  // panel proxy — allow-list those dev origins so the Next 16 dev runtime accepts
  // the proxied requests (blocked origins degrade the client bootstrap/hydration).
  allowedDevOrigins: ["127.0.0.1", "localhost", "127.0.0.1:81", "localhost:81"],
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // hide the floating dev-tools overlay — it overlaps the sticky footer in the preview
  devIndicators: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;

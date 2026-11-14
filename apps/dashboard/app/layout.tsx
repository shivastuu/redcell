import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "RedCell Leaderboard",
  description: "Attacks against AI agents behind real MCP servers: attack success, guardrails, false alarms.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "RedCell — Leaderboard",
  description: "Adversarial robustness of a fintech agent, before vs after the layered defense.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

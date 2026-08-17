import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BallotProof | Evidence, not trust",
  description: "Independent, reproducible evidence infrastructure for election results.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

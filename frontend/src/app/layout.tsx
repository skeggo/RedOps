import type { Metadata } from "next";
import Link from "next/link";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AI Red Team Operator",
  description: "Scans, findings, and MITRE mapping",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        <div className="appShell">
          <header className="topBar">
            <div className="container topBarInner">
              <div className="brand">
                <Link href="/scans">AI Red Team Operator</Link>
              </div>
              <nav className="nav">
                <Link href="/scans">Scans</Link>
                <Link href="/scans/new">Create scan</Link>
              </nav>
            </div>
          </header>
          <main className="container main">{children}</main>
          <footer className="container footer">
            <span className="muted">
              API base: {process.env.NEXT_PUBLIC_API_BASE_URL || "(not set)"}
            </span>
          </footer>
        </div>
      </body>
    </html>
  );
}

import type { Metadata } from "next";

export const metadata: Metadata = { title: "DadaDevourer", description: "Security testing platform" };
export default function RootLayout({ children }: Readonly<{children: React.ReactNode}>) { return <html lang="en"><body>{children}</body></html>; }

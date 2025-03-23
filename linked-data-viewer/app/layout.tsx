import "@/styles/globals.css";

import { siteConfig } from "@/config/site";
import clsx from "clsx";
import type { Metadata, Viewport } from "next";
import { Inter as FontSans } from "next/font/google";
import { Providers } from "./providers";

const fontSans = FontSans({
    subsets: ["latin"],
    variable: "--font-sans",
});

export const metadata: Metadata = {
    title: {
        default: siteConfig.name,
        template: `%s - ${siteConfig.name}`,
    },
    description: siteConfig.description,
};

export const viewport: Viewport = {
    themeColor: [
        { media: "(prefers-color-scheme: light)", color: "white" },
        { media: "(prefers-color-scheme: dark)", color: "black" },
    ],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html suppressHydrationWarning={true} lang="en">
            <head />
            <body className={clsx("min-h-screen bg-background font-sans antialiased", fontSans.className)}>
                <Providers themeProps={{ attribute: "class", defaultTheme: "light" }}>
                    <div className="h-dvh w-dvw">{children}</div>
                </Providers>
            </body>
        </html>
    );
}

import "./globals.css";

export const metadata = {
  title: "AWS Cloud Autopilot",
  description: "AWS security, cost and AI operations MVP"
};

export default function RootLayout({ children }) {
  return <html><body>{children}</body></html>;
}

import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Pikify · SNI Intelligence',
  description: 'Measure public TLS hosts and evaluate TLS and REALITY compatibility signals.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" dir="ltr"><body>{children}</body></html>;
}

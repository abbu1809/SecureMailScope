import React from 'react';
import { Outlet } from 'react-router-dom';
import { Navbar } from './Navbar';
import { Footer } from './Footer';

export const AppShell: React.FC = () => {
  return (
    <div className="min-h-screen flex flex-col bg-canvas text-ink font-sans selection:bg-accent selection:text-white">
      {/* Top Floating Nav */}
      <Navbar />

      {/* Main Page Body */}
      <main className="flex-1 w-full">
        <Outlet />
      </main>

      {/* Near-Black Inverse Footer */}
      <Footer />
    </div>
  );
};

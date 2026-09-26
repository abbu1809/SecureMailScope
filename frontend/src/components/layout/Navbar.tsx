import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ShieldCheck, Terminal, BookOpen, FileText, Cpu, ArrowUpRight, Menu, X } from 'lucide-react';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { name: 'Dashboard', path: '/dashboard', icon: Cpu },
    { name: 'Rules Directory', path: '/rules', icon: BookOpen },
    { name: 'Audit Reports', path: '/reports', icon: FileText },
    { name: 'Playground', path: '/playground', icon: Terminal },
  ];

  return (
    <header className="sticky top-4 z-50 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      <nav className="nav-pill shadow-subtle border border-hairline/80 bg-white/95 backdrop-blur-md transition-all">
        {/* Brand Logomark */}
        <Link to="/" className="flex items-center gap-2.5 group shrink-0" onClick={() => setMobileMenuOpen(false)}>
          <div className="w-8 h-8 rounded-[30%] bg-ink flex items-center justify-center text-white transition-transform group-hover:scale-105 shadow-sm">
            <ShieldCheck className="w-4 h-4 text-white" />
          </div>
          <div className="flex flex-col">
            <span className="font-bold text-ink tracking-tight text-base leading-none">
              SecureMailScope<span className="text-accent font-extrabold">.</span>
            </span>
            <span className="text-[10px] font-semibold text-text-muted tracking-wider uppercase mt-0.5">
              SIH PS 26159
            </span>
          </div>
        </Link>

        {/* Desktop Navigation Links */}
        <div className="hidden md:flex items-center gap-1">
          {navLinks.map((item) => {
            const isActive = location.pathname.startsWith(item.path);
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`px-3.5 py-1.5 rounded-full text-xs font-semibold transition-all duration-150 flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-canvas text-ink shadow-subtle border border-hairline/80'
                    : 'text-text-muted hover:text-ink hover:bg-canvas-soft/80'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {item.name}
              </Link>
            );
          })}
        </div>

        {/* Action Button & Mobile Toggle */}
        <div className="flex items-center gap-2">
          <Link
            to="/dashboard"
            className="btn-primary text-xs py-2 px-4 flex items-center gap-1 shadow-sm"
          >
            <span>Live Analysis</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>

          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-full hover:bg-canvas-soft text-text-muted hover:text-ink transition-colors"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-2 p-4 bg-white/95 backdrop-blur-md rounded-2xl border border-hairline shadow-lg space-y-2 animate-fadeIn">
          {navLinks.map((item) => {
            const isActive = location.pathname.startsWith(item.path);
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className={`w-full px-4 py-2.5 rounded-full text-xs font-semibold flex items-center gap-2.5 transition-all ${
                  isActive
                    ? 'bg-ink text-white'
                    : 'text-text-muted hover:text-ink hover:bg-canvas-soft'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </div>
      )}
    </header>
  );
};


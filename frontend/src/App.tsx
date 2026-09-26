import React from 'react';
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { RulesPage } from './pages/RulesPage';
import { ReportsPage } from './pages/ReportsPage';
import { LivePlaygroundPage } from './pages/LivePlaygroundPage';

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      {
        index: true,
        element: <LandingPage />,
      },
      {
        path: 'dashboard',
        element: <DashboardPage />,
      },
      {
        path: 'rules',
        element: <RulesPage />,
      },
      {
        path: 'reports',
        element: <ReportsPage />,
      },
      {
        path: 'playground',
        element: <LivePlaygroundPage />,
      },
      {
        path: '*',
        element: <Navigate to="/" replace />,
      },
    ],
  },
]);

export const App: React.FC = () => {
  return <RouterProvider router={router} />;
};

export default App;

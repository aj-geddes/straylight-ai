import { BrowserRouter, Routes, Route, useParams, useNavigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { ServiceConfig } from './pages/ServiceConfig';
import { Help } from './pages/Help';

function ServiceConfigRoute() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();

  if (!name) return null;

  return <ServiceConfig name={name} onBack={() => navigate('/')} />;
}

/**
 * Root application component with client-side routing.
 * Routes: / -> Dashboard, /services/:name -> ServiceConfig
 */
export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={
            <Layout currentPath="/">
              <Dashboard />
            </Layout>
          }
        />
        <Route
          path="/services"
          element={
            <Layout currentPath="/services">
              <Dashboard />
            </Layout>
          }
        />
        <Route
          path="/services/:name"
          element={
            <Layout currentPath="/services">
              <ServiceConfigRoute />
            </Layout>
          }
        />
        <Route
          path="/help"
          element={
            <Layout currentPath="/help">
              <Help />
            </Layout>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

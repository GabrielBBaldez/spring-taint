import { Nav } from "./components/Nav";
import { Footer } from "./components/Footer";
import { Home } from "./pages/Home";
import { DashboardPage } from "./pages/DashboardPage";
import { Catches } from "./pages/Catches";
import { Coverage } from "./pages/Coverage";
import { useHashRoute } from "./lib/useHashRoute";

export default function App() {
  const route = useHashRoute();
  return (
    <>
      <div className="grain" aria-hidden />
      <div className="glow" aria-hidden />

      <Nav route={route} />

      {route === "home" && <Home />}
      {route === "dashboard" && <DashboardPage />}
      {route === "catches" && <Catches />}
      {route === "coverage" && <Coverage />}

      <Footer />
    </>
  );
}

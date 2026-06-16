import { useEffect, useState } from "react";

export type Route = "home" | "dashboard" | "catches" | "coverage";

const ROUTES: Route[] = ["home", "dashboard", "catches", "coverage"];

function current(): Route {
  const h = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  return (ROUTES as string[]).includes(h) ? (h as Route) : "home";
}

/** Minimal dependency-free hash router, so the site is a static SPA (GitHub Pages-safe). */
export function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(current());
  useEffect(() => {
    const onHash = () => {
      setRoute(current());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return route;
}

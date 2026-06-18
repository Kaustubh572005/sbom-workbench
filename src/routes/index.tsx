import { createFileRoute, redirect } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/")({
  beforeLoad: async () => {
    if (typeof window === "undefined") return;
    const { data } = await supabase.auth.getUser();
    if (!data.user) throw redirect({ to: "/auth" });
    // signed in users see the authenticated dashboard, which lives at the same URL
    // under _authenticated layout — no redirect needed; just let it render.
  },
  // This route is shadowed by /_authenticated/index.tsx when signed in.
  // For unsigned users, beforeLoad redirects to /auth before render.
  component: () => null,
});

import { createFileRoute, Outlet, redirect, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { WorkbenchProvider, Sidebar, Header, AIPanel, DetailDrawer } from "@/lib/workbench-shared";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    if (typeof window === "undefined") return;
    const { data, error } = await supabase.auth.getUser();
    if (error || !data.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: AuthenticatedLayout,
});

function AuthenticatedLayout() {
  const navigate = useNavigate();
  const [email, setEmail] = useState<string | undefined>(undefined);

  useEffect(() => {
    void supabase.auth.getUser().then(({ data }) => setEmail(data.user?.email));
    const { data: sub } = supabase.auth.onAuthStateChange((event) => {
      if (event === "SIGNED_OUT") navigate({ to: "/auth", replace: true });
    });
    return () => { sub.subscription.unsubscribe(); };
  }, [navigate]);

  async function onSignOut() {
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  return (
    <WorkbenchProvider>
      <div className="min-h-screen text-foreground">
        <Header userEmail={email} onSignOut={() => void onSignOut()} />
        <div className="mx-auto flex max-w-[1600px] gap-6 px-4 py-6 sm:px-6 lg:px-8">
          <Sidebar />
          <main className="min-w-0 flex-1 space-y-6">
            <Outlet />
          </main>
          <AIPanel />
        </div>
        <DetailDrawer />
      </div>
    </WorkbenchProvider>
  );
}

import { createFileRoute, Outlet, redirect, useNavigate, useRouterState } from "@tanstack/react-router";
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
      <AuthenticatedShell userEmail={email} onSignOut={() => void onSignOut()} />
    </WorkbenchProvider>
  );
}

function AuthenticatedShell({ userEmail, onSignOut }: { userEmail?: string; onSignOut: () => void }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const { loading, uploading } = useWorkbench();
  const busy = loading || uploading;

  return (
    <div className="min-h-screen text-foreground">
      {busy && <div className="route-progress fixed inset-x-0 top-0 z-50 h-0.5 bg-primary" aria-label="Loading" />}
      <Header userEmail={userEmail} onSignOut={onSignOut} />
      <div className="mx-auto flex max-w-[1600px] gap-6 px-4 py-6 sm:px-6 lg:px-8">
        <Sidebar />
        <main key={pathname} className="page-enter min-w-0 flex-1 space-y-6">
          {loading ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="Loading workspace">
              {Array.from({ length: 8 }, (_, i) => <div key={i} className="skeleton h-28 border border-border/40" />)}
            </div>
          ) : <Outlet />}
        </main>
        <AIPanel />
      </div>
      <DetailDrawer />
    </div>
  );
}

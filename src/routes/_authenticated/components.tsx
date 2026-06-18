import { createFileRoute } from "@tanstack/react-router";
import { AnimatePresence } from "framer-motion";
import {
  useWorkbench, ActiveFilterChip, SearchBar, AdvisoryCard, EmptyState,
  SkeletonList, NoDataset, KpiRow,
} from "@/lib/workbench-shared";

export const Route = createFileRoute("/_authenticated/components")({
  head: () => ({ meta: [{ title: "Components — SBOM Workbench" }] }),
  component: ComponentsPage,
});

function ComponentsPage() {
  const { active, loading, filteredComponents, searchQuery, severityFilter } = useWorkbench();
  if (!active) return <NoDataset />;
  return (
    <>
      <KpiRow />
      <ActiveFilterChip />
      <SearchBar />
      <div className="space-y-3">
        {loading ? <SkeletonList /> :
          filteredComponents.length === 0 ? <EmptyState searching={!!searchQuery || severityFilter !== "all"} /> :
            (<AnimatePresence initial={false}>
              {filteredComponents.map((row, i) => <AdvisoryCard key={row.id} row={row} index={i} />)}
            </AnimatePresence>)}
      </div>
    </>
  );
}

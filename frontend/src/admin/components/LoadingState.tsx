export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="adm-loading-state" role="status">
      <span className="adm-spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

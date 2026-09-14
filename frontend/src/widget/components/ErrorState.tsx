export function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="ss-error-state" role="alert">
      <p className="ss-error-state__title">Couldn&apos;t load security signals</p>
      <p className="ss-error-state__body">Please check your connection and try again.</p>
      <button type="button" className="ss-button ss-button--retry" onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}

import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Rendu de repli personnalisé. */
  fallback?: ReactNode;
  onError?: (error: Error, info: ErrorInfo) => void;
}

export interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Filet de sécurité de rendu : une erreur d'un panneau ne doit pas blanchir la
 * console entière (et surtout pas masquer l'état `dry_run`/`autonomy`).
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    this.props.onError?.(error, info);
    if (typeof console !== 'undefined') {
      console.error('[Thot Secure] erreur de rendu interceptée', error, info.componentStack);
    }
  }

  private readonly handleReset = (): void => {
    this.setState({ error: null });
  };

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback !== undefined) return this.props.fallback;

    return (
      <div
        role="alert"
        className="m-4 rounded-lg border border-rose-800 bg-rose-950/40 p-4 text-sm text-rose-100"
      >
        <p className="font-semibold">Une erreur d’affichage est survenue.</p>
        <p className="mt-1 break-words text-xs text-rose-200/80">{error.message}</p>
        <button
          type="button"
          onClick={this.handleReset}
          className="mt-3 rounded border border-rose-700 bg-rose-900/60 px-3 py-1 text-xs font-medium text-rose-50 hover:bg-rose-900"
        >
          Réessayer
        </button>
      </div>
    );
  }
}

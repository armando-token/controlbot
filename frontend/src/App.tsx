import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppShell } from './app/shell/AppShell';
import { reportClientError } from './lib/diagnostics';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

interface BoundaryState {
  hasError: boolean;
  errorMessage: string;
}

class DiagnosticsErrorBoundary extends React.Component<
  { children: React.ReactNode },
  BoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: Error): BoundaryState {
    return {
      hasError: true,
      errorMessage: error?.message || 'Unexpected UI error',
    };
  }

  override componentDidCatch(error: Error, info: React.ErrorInfo): void {
    reportClientError({
      kind: 'react_error_boundary',
      message: `${error.name}: ${error.message}`,
      stack: error.stack ?? null,
      component_stack: info.componentStack ?? null,
    });
  }

  override render(): React.ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-[#FFFFFF] p-6 text-[#111827]">
          <div className="max-w-md rounded-xl border border-[#E5E7EB] bg-[#F9FAFB] p-6 shadow-sm">
            <h1 className="text-base font-semibold text-[#111827]">
              ControlBot Studio encountered a UI error
            </h1>
            <p className="mt-2 break-words text-sm text-[#4B5563]">
              {this.state.errorMessage}
            </p>
            <p className="mt-2 text-xs text-[#6B7280]">
              This failure was automatically logged to server diagnostics.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="mt-4 rounded-lg bg-[#111827] px-3.5 py-2 text-xs font-medium text-white hover:bg-[#1F2937]"
            >
              Reload Studio
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export const App: React.FC = () => {
  return (
    <DiagnosticsErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AppShell />
      </QueryClientProvider>
    </DiagnosticsErrorBoundary>
  );
};

export default App;

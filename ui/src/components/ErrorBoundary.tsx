import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Show what went wrong instead of unmounting to a blank window.
 *
 * React tears the whole tree down on an uncaught render error, so one bad
 * field in one component used to leave the app as an empty dark rectangle
 * with nothing to act on — the same failure shape as a scan that dies
 * without emitting an error.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("laninv UI crashed:", error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="crash">
        <h2>The interface hit an error</h2>
        <p className="muted">
          Your inventory is untouched — this is a display fault. Reopen the app
          to try again, and report the details below.
        </p>
        <pre>{error.message}</pre>
        {error.stack && <pre className="muted small">{error.stack}</pre>}
      </div>
    );
  }
}

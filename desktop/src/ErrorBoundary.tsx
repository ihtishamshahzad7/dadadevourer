import React from "react";
import type { ErrorInfo, ReactNode } from "react";

type Props = { children: ReactNode };
type State = { hasError: boolean; message: string };

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, message: "" };

  static getDerivedStateFromError(error: unknown): State {
    return {
      hasError: true,
      message: error instanceof Error ? error.message : String(error),
    };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error("DadaDevourer UI error", error, info);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="loading-screen">
        <div className="loading-mark">DD</div>
        <b>DadaDevourer could not display this screen</b>
        <span>{this.state.message || "An unexpected application error occurred."}</span>
        <button onClick={() => window.location.reload()}>Restart application view</button>
      </div>
    );
  }
}

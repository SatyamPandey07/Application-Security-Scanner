import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import SecurityDashboard from '../components/SecurityDashboard';
import FindingDetailModal from '../components/FindingDetailModal';

const mockFindings = [
  {
    id: 101,
    rule_id: 'python-sql-injection',
    source: 'sast',
    severity_raw: 'HIGH',
    cvss_score: 8.5,
    file_path: 'backend/app/routes/search.py',
    line_number: 42,
    plain_title: 'Your search box can be tricked into running harmful code',
    plain_location: 'The search bar on your homepage',
    plain_whats_wrong: 'An input field allows running arbitrary database queries.',
    plain_real_world_impact: 'Attackers could read or modify database data.',
    plain_risk_level: 'Fix this now - High impact on database security',
    plain_what_to_do: 'Use parameterized SQL queries.',
    feature_area: 'Search & Browsing',
    ai_explanation: 'Technical explanation of SQL injection.',
    code_snippet: 'db.execute(f"SELECT * FROM users WHERE q={query}")'
  },
  {
    id: 102,
    rule_id: 'hardcoded-jwt-secret',
    source: 'secret',
    severity_raw: 'CRITICAL',
    cvss_score: 9.8,
    file_path: 'backend/app/core/config.py',
    line_number: 15,
    plain_title: 'Secret key is exposed in application configuration',
    plain_location: 'The user login page',
    plain_whats_wrong: 'JWT secret is hardcoded in source file.',
    plain_real_world_impact: 'Attackers could forge authentication tokens.',
    plain_risk_level: 'Fix this now - Critical authentication flaw',
    plain_what_to_do: 'Move secret key to environment variable.',
    feature_area: 'Login & Accounts',
    ai_explanation: 'Hardcoded secret key explanation.',
    code_snippet: 'SECRET_KEY = "supersecretkey"'
  }
];

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  global.fetch = vi.fn().mockImplementation(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve(mockFindings),
    })
  );
});

describe('Plain-Language Dashboard & Finding View', () => {
  it('Simple mode never renders a file path or CVSS number', async () => {
    // 1. Render SecurityDashboard in Simple mode
    localStorage.setItem('sentinel_view_mode', 'simple');
    render(<SecurityDashboard scanId="scan-123" token="fake-token" />);

    await waitFor(() => {
      expect(screen.getByTestId('simple-view')).toBeInTheDocument();
    });

    // In simple dashboard view, file path and CVSS score should be absent
    expect(screen.queryByText(/backend\/app\/routes\/search\.py/)).toBeNull();
    expect(screen.queryByText(/backend\/app\/core\/config\.py/)).toBeNull();
    expect(screen.queryByText('8.5')).toBeNull();
    expect(screen.queryByText('9.8')).toBeNull();
    expect(screen.queryByText('python-sql-injection')).toBeNull();

    // 2. Render FindingDetailModal in Simple mode
    render(
      <FindingDetailModal
        finding={mockFindings[0]}
        token="fake-token"
        simpleDefault={true}
        onClose={() => {}}
      />
    );

    expect(screen.getByTestId('finding-modal')).toBeInTheDocument();
    expect(screen.getByTestId('modal-plain-title')).toHaveTextContent(
      'Your search box can be tricked into running harmful code'
    );
    expect(screen.getByTestId('modal-plain-location')).toHaveTextContent(
      'The search bar on your homepage'
    );

    // Verify technical details are completely absent in Simple mode
    expect(screen.queryByTestId('technical-panel')).toBeNull();
    expect(screen.queryByText('backend/app/routes/search.py:42')).toBeNull();
    expect(screen.queryByText(/8\.5 \/ 10\.0/)).toBeNull();
    expect(screen.queryByTestId('modal-rule-id')).toBeNull();
  });

  it('The toggle persists across a page reload', async () => {
    // Start with default simple view
    const { unmount } = render(<SecurityDashboard scanId="scan-123" token="fake-token" />);
    await waitFor(() => {
      expect(screen.getByTestId('simple-view')).toBeInTheDocument();
    });

    // Click toggle to switch to Technical view
    const toggleBtn = screen.getByTestId('view-toggle');
    fireEvent.click(toggleBtn);

    await waitFor(() => {
      expect(screen.getByTestId('technical-view')).toBeInTheDocument();
    });
    expect(localStorage.getItem('sentinel_view_mode')).toBe('technical');

    // Simulate page reload by unmounting and re-rendering
    unmount();

    render(<SecurityDashboard scanId="scan-123" token="fake-token" />);
    await waitFor(() => {
      expect(screen.getByTestId('technical-view')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('simple-view')).toBeNull();
  });

  it("Switching one card to technical mode doesn't affect other cards", async () => {
    render(<SecurityDashboard scanId="scan-123" token="fake-token" />);
    await waitFor(() => {
      expect(screen.getByTestId('simple-view')).toBeInTheDocument();
    });

    const cards = screen.getAllByTestId('simple-finding-card');
    expect(cards).toHaveLength(2);

    const showTechButtons = screen.getAllByTestId('show-technical-btn');
    
    // Grouping puts 'Login & Accounts' (Finding 102) first, then 'Search & Browsing' (Finding 101)
    // Click "Show technical details" on card 0 (Finding 102)
    fireEvent.click(showTechButtons[0]);

    // Modal for Finding 102 should open in Technical mode
    await waitFor(() => {
      expect(screen.getByTestId('finding-modal')).toBeInTheDocument();
    });
    expect(screen.getByTestId('technical-panel')).toBeInTheDocument();
    expect(screen.getByTestId('tech-rule-id')).toHaveTextContent('hardcoded-jwt-secret');

    // Close the modal
    const closeBtn = screen.getByTestId('modal-close');
    fireEvent.click(closeBtn);

    // Now click the second card (Finding 101) normally (without clicking "Show technical details")
    const updatedCards = screen.getAllByTestId('simple-finding-card');
    fireEvent.click(updatedCards[1]);

    // Modal for Finding 101 must still open in Simple mode
    await waitFor(() => {
      expect(screen.getByTestId('finding-modal')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('technical-panel')).toBeNull();
    expect(screen.getByTestId('modal-plain-title')).toHaveTextContent(
      'Your search box can be tricked into running harmful code'
    );
  });
});

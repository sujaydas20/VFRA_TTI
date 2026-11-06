import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { LandingPage } from './components/LandingPage';
import { Login } from './pages/Login';
import { ThreatIntelOverview } from './pages/ThreatIntelOverview';
import { ChannelManagement } from './pages/ChannelManagement';
import { SearchThreadDetail } from './pages/SearchThreadDetail';
import { CreditQuota } from './pages/CreditQuota';
import { AuditViewer } from './pages/AuditViewer';
import { Settings } from './pages/Settings';
import { PlatformAdminDashboard } from './pages/PlatformAdminDashboard';
import { OrgAdminDashboard } from './pages/OrgAdminDashboard';
import { OrgApproval } from './pages/OrgApproval';
import { UserMembershipManagement } from './pages/UserMembershipManagement';
import { RoleSubsystemAccess } from './pages/RoleSubsystemAccess';
import { EvidenceDetailReportPreview } from './pages/EvidenceDetailReportPreview';
import { ApiManagement } from './pages/ApiManagement';

export const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        {/* Public landing page - premium homepage */}
        <Route path="/" element={<LandingPage />} />

        {/* Public standalone login route */}
        <Route path="/login" element={<Login />} />

        {/* Authenticated routes wrapped in shared AppShell */}
        <Route element={<AppShell />}>
          <Route path="/threat-intel" element={<ThreatIntelOverview />} />
          <Route path="/channels" element={<ChannelManagement />} />
          <Route path="/search-thread" element={<SearchThreadDetail />} />
          <Route path="/credit-quota" element={<CreditQuota />} />
          <Route path="/audit" element={<AuditViewer />} />
          <Route path="/platform-admin" element={<PlatformAdminDashboard />} />
          <Route path="/org-admin" element={<OrgAdminDashboard />} />
          <Route path="/org-approval" element={<OrgApproval />} />
          <Route path="/user-membership" element={<UserMembershipManagement />} />
          <Route path="/role-subsystem" element={<RoleSubsystemAccess />} />
          <Route path="/evidence-detail" element={<EvidenceDetailReportPreview />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/api-management" element={<ApiManagement />} />
          <Route path="*" element={<Navigate to="/threat-intel" replace />} />
        </Route>
      </Routes>
    </Router>
  );
};

export default App;

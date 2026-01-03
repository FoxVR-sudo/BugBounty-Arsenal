import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { FiUsers, FiUserPlus, FiTrash2, FiMail, FiCopy, FiCheck, FiShield, FiEye } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import { useTheme } from '../contexts/ThemeContext';

const TeamManagement = () => {
  const { isDark } = useTheme();
  const [team, setTeam] = useState(null);
  const [members, setMembers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Create team form
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [teamName, setTeamName] = useState('');
  
  // Invite member form
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  
  // Copied invite code state
  const [copiedCode, setCopiedCode] = useState(false);

  useEffect(() => {
    fetchTeamData();
  }, []);

  const fetchTeamData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      
      // Fetch user's team
      const teamResponse = await axios.get(process.env.REACT_APP_API_URL + '/teams/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (teamResponse.data.results && teamResponse.data.results.length > 0) {
        const userTeam = teamResponse.data.results[0];
        setTeam(userTeam);
        
        // Fetch team members
        const membersResponse = await axios.get(
          `${process.env.REACT_APP_API_URL}/teams/${userTeam.id}/members/`,
          { headers: { 'Authorization': `Bearer ${token}` } }
        );
        setMembers(membersResponse.data);
        
        // Fetch pending invitations
        const invitationsResponse = await axios.get(
          `${process.env.REACT_APP_API_URL}/teams/${userTeam.id}/invitations/`,
          { headers: { 'Authorization': `Bearer ${token}` } }
        );
        setInvitations(invitationsResponse.data);
      }
    } catch (err) {
      setError('Failed to load team data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        process.env.REACT_APP_API_URL + '/teams/',
        { name: teamName },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setSuccess('Team created successfully!');
      setShowCreateTeam(false);
      setTeamName('');
      fetchTeamData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create team');
    }
  };

  const handleInviteMember = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${process.env.REACT_APP_API_URL}/teams/${team.id}/invite/`,
        { email: inviteEmail, role: inviteRole },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setSuccess('Invitation sent successfully!');
      setShowInvite(false);
      setInviteEmail('');
      setInviteRole('member');
      fetchTeamData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send invitation');
    }
  };

  const handleRemoveMember = async (memberId) => {
    if (!window.confirm('Are you sure you want to remove this member?')) return;
    
    try {
      const token = localStorage.getItem('token');
      await axios.delete(
        `${process.env.REACT_APP_API_URL}/teams/${team.id}/members/${memberId}/`,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setSuccess('Member removed successfully');
      fetchTeamData();
    } catch (err) {
      setError('Failed to remove member');
    }
  };

  const handleCopyInviteCode = () => {
    if (team?.invite_code) {
      navigator.clipboard.writeText(team.invite_code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    }
  };

  const getRoleBadge = (role) => {
    const styles = {
      admin: 'bg-red-100 text-red-700 border-red-200',
      member: 'bg-blue-100 text-blue-700 border-blue-200',
      viewer: 'bg-gray-100 text-gray-700 border-gray-200',
    };
    return styles[role] || styles.viewer;
  };

  const getRoleIcon = (role) => {
    if (role === 'admin') return <FiShield size={16} />;
    if (role === 'member') return <FiUsers size={16} />;
    return <FiEye size={16} />;
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="p-8 flex items-center justify-center">
          <div className="text-gray-500">Loading team data...</div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8">
          <h1 className={`text-3xl font-bold mb-2 ${isDark ? 'text-white' : 'text-gray-900'}`}>Team Management</h1>
          <p className="text-gray-600">Collaborate with your team members on security scans</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
            {error}
          </div>
        )}

        {success && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg text-green-700">
            {success}
          </div>
        )}

        {!team ? (
          <div className="bg-white rounded-lg shadow-lg p-12 text-center">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-primary bg-opacity-10 rounded-full mb-6">
              <FiUsers className="text-primary" size={40} />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">No Team Yet</h2>
            <p className="text-gray-600 mb-6">Create a team to collaborate with others</p>
            <button
              onClick={() => setShowCreateTeam(true)}
              className="px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition font-semibold"
            >
              Create Team
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Team Info Card */}
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">{team.name}</h2>
                  <p className="text-gray-600 text-sm mt-1">
                    {members.length} / {team.max_members || 10} members
                  </p>
                </div>
                <button
                  onClick={() => setShowInvite(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
                >
                  <FiUserPlus /> Invite Member
                </button>
              </div>

              {/* Invite Code */}
              <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 mb-1">Team Invite Code</h4>
                    <p className="text-xs text-gray-500">Share this code with team members to join</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <code className="px-4 py-2 bg-white border border-gray-300 rounded font-mono text-lg">
                      {team.invite_code}
                    </code>
                    <button
                      onClick={handleCopyInviteCode}
                      className="p-2 bg-white border border-gray-300 rounded hover:bg-gray-50 transition"
                      title="Copy invite code"
                    >
                      {copiedCode ? <FiCheck className="text-green-600" /> : <FiCopy />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Team Members */}
            <div className="bg-white rounded-lg shadow">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-xl font-bold text-gray-900">Team Members</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {members.map((member) => (
                  <div key={member.id} className="p-6 flex items-center justify-between hover:bg-gray-50">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 bg-primary bg-opacity-10 rounded-full flex items-center justify-center">
                        <span className="text-primary font-bold">
                          {member.user.email.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900">{member.user.email}</h4>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs px-2 py-1 rounded border font-semibold flex items-center gap-1 ${getRoleBadge(member.role)}`}>
                            {getRoleIcon(member.role)}
                            {member.role.toUpperCase()}
                          </span>
                          {member.permissions.can_create_scans && (
                            <span className="text-xs text-gray-500">• Can create scans</span>
                          )}
                          {member.permissions.can_manage_members && (
                            <span className="text-xs text-gray-500">• Can manage members</span>
                          )}
                        </div>
                      </div>
                    </div>
                    {member.role !== 'admin' && (
                      <button
                        onClick={() => handleRemoveMember(member.id)}
                        className="p-2 text-red-600 hover:bg-red-50 rounded transition"
                        title="Remove member"
                      >
                        <FiTrash2 />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Pending Invitations */}
            {invitations.length > 0 && (
              <div className="bg-white rounded-lg shadow">
                <div className="p-6 border-b border-gray-200">
                  <h3 className="text-xl font-bold text-gray-900">Pending Invitations</h3>
                </div>
                <div className="divide-y divide-gray-200">
                  {invitations.map((invitation) => (
                    <div key={invitation.id} className="p-6 flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <FiMail className="text-gray-400" size={20} />
                        <div>
                          <h4 className="font-semibold text-gray-900">{invitation.email}</h4>
                          <p className="text-xs text-gray-500 mt-1">
                            Invited {new Date(invitation.created_at).toLocaleDateString()} • Expires {new Date(invitation.expires_at).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <span className={`text-xs px-3 py-1 rounded border font-semibold ${getRoleBadge(invitation.role)}`}>
                        {invitation.role.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Create Team Modal */}
        {showCreateTeam && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-8 max-w-md w-full">
              <h3 className="text-2xl font-bold mb-6">Create Team</h3>
              <form onSubmit={handleCreateTeam}>
                <div className="mb-6">
                  <label className="block text-gray-700 font-semibold mb-2">Team Name</label>
                  <input
                    type="text"
                    value={teamName}
                    onChange={(e) => setTeamName(e.target.value)}
                    placeholder="My Security Team"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    required
                  />
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="flex-1 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition font-semibold"
                  >
                    Create Team
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowCreateTeam(false)}
                    className="flex-1 px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Invite Member Modal */}
        {showInvite && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-8 max-w-md w-full">
              <h3 className="text-2xl font-bold mb-6">Invite Team Member</h3>
              <form onSubmit={handleInviteMember}>
                <div className="mb-4">
                  <label className="block text-gray-700 font-semibold mb-2">Email Address</label>
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="colleague@example.com"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    required
                  />
                </div>
                <div className="mb-6">
                  <label className="block text-gray-700 font-semibold mb-2">Role</label>
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  >
                    <option value="viewer">Viewer - Can only view scans</option>
                    <option value="member">Member - Can create and view scans</option>
                    <option value="admin">Admin - Full access</option>
                  </select>
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="flex-1 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition font-semibold"
                  >
                    Send Invitation
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowInvite(false)}
                    className="flex-1 px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default TeamManagement;

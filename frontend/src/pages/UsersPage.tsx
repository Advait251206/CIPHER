import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Users, Trash2, Key, Save, X } from 'lucide-react';
import { api } from '../api/client';
import { VulnerableUser } from '../api/types';
import { Toast, ToastType } from '../components/common/Toast';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { pageBody, card, cardHeader, cardTitle, controlBtn, formInput } from '../ui/classes';
import { cn } from '../lib/cn';

export const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<VulnerableUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [newPassword, setNewPassword] = useState('');
  
  const [toast, setToast] = useState<{ message: string; type: ToastType; visible: boolean }>({
    message: '',
    type: 'info',
    visible: false
  });
  const [userToDelete, setUserToDelete] = useState<number | null>(null);

  const showToast = (message: string, type: ToastType = 'info') => {
    setToast({ message, type, visible: true });
  };

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const data = await api.vulnerableUsers.list();
      setUsers(data);
    } catch (e: any) {
      showToast(e.message || 'Failed to fetch users', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleDelete = (id: number) => {
    setUserToDelete(id);
  };

  const confirmDeleteUser = async () => {
    if (userToDelete === null) return;
    try {
      await api.vulnerableUsers.delete(userToDelete);
      showToast('User deleted successfully', 'success');
      fetchUsers();
    } catch (e: any) {
      showToast(e.message || 'Failed to delete user', 'error');
    } finally {
      setUserToDelete(null);
    }
  };

  const handleUpdatePassword = async (id: number) => {
    if (!newPassword) return;
    try {
      await api.vulnerableUsers.updatePassword(id, { new_password: newPassword });
      showToast('Password updated successfully', 'success');
      setEditingId(null);
      setNewPassword('');
      fetchUsers();
    } catch (e: any) {
      showToast(e.message || 'Failed to update password', 'error');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className={pageBody}
    >
      <div className="flex justify-between items-end mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-fg flex items-center gap-3">
            <Users size={24} color="var(--color-accent)" />
            Vulnerable App Users
          </h1>
          <p className="text-[0.88rem] text-fg-muted mt-1 max-w-2xl">
            Directly access and manage the mock user database of the vulnerable application target. 
            Modifying data here directly reflects in the vulnerable app.
          </p>
        </div>
      </div>

      <div className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>User Database (SQLite)</div>
        </div>
        
        {loading ? (
          <div className="p-8 text-center text-fg-muted">Loading users...</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-fg-muted">No users found in database.</div>
        ) : (
          <div className="overflow-x-auto rounded-[6px] border border-line mt-2">
            <table className="w-full text-left border-collapse text-[0.8rem]">
              <thead>
                <tr className="bg-[rgba(15,23,42,0.4)] border-b border-line text-[0.72rem] text-fg-muted uppercase tracking-wider">
                  <th className="px-4 py-3 font-semibold">ID</th>
                  <th className="px-4 py-3 font-semibold">Username</th>
                  <th className="px-4 py-3 font-semibold">Full Name</th>
                  <th className="px-4 py-3 font-semibold">Email</th>
                  <th className="px-4 py-3 font-semibold">Password (Cleartext)</th>
                  <th className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id} className="border-b border-line hover:bg-surface-hover transition-colors">
                    <td className="px-4 py-3 text-fg-muted font-mono">{user.id}</td>
                    <td className="px-4 py-3 text-fg font-medium">{user.username}</td>
                    <td className="px-4 py-3 text-fg-2">{user.full_name}</td>
                    <td className="px-4 py-3 text-fg-2 font-mono text-[0.75rem]">{user.email}</td>
                    <td className="px-4 py-3 text-crit font-mono text-[0.75rem]">
                      {editingId === user.id ? (
                        <div className="flex items-center gap-2">
                          <input 
                            type="text" 
                            className={cn(formInput, 'py-1 px-2 text-[0.75rem] w-32')}
                            value={newPassword}
                            onChange={e => setNewPassword(e.target.value)}
                            placeholder="New password"
                          />
                        </div>
                      ) : (
                        user.password
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {editingId === user.id ? (
                          <>
                            <button 
                              onClick={() => handleUpdatePassword(user.id)}
                              className="p-[0.35rem] rounded-[4px] bg-benign text-black hover:bg-benign-muted transition-colors"
                              title="Save Password"
                            >
                              <Save size={14} />
                            </button>
                            <button 
                              onClick={() => { setEditingId(null); setNewPassword(''); }}
                              className="p-[0.35rem] rounded-[4px] bg-surface text-fg-muted hover:text-fg transition-colors"
                              title="Cancel"
                            >
                              <X size={14} />
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              onClick={() => { setEditingId(user.id); setNewPassword(user.password); }}
                              className="p-[0.35rem] rounded-[4px] bg-[rgba(30,41,59,0.5)] text-fg-muted hover:text-fg hover:bg-[rgba(30,41,59,1)] transition-colors"
                              title="Change Password"
                            >
                              <Key size={14} />
                            </button>
                            <button 
                              onClick={() => handleDelete(user.id)}
                              className="p-[0.35rem] rounded-[4px] bg-[rgba(153,27,27,0.2)] text-crit hover:bg-[rgba(153,27,27,0.4)] transition-colors"
                              title="Delete User"
                            >
                              <Trash2 size={14} />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Toast 
        message={toast.message} 
        type={toast.type} 
        isVisible={toast.visible} 
        onClose={() => setToast(prev => ({ ...prev, visible: false }))} 
      />

      <ConfirmDialog
        isOpen={userToDelete !== null}
        onClose={() => setUserToDelete(null)}
        onConfirm={confirmDeleteUser}
        title="Delete User"
        message="Are you sure you want to delete this user? Modifying the database here directly reflects in the vulnerable application target."
        confirmLabel="Delete"
        isDestructive={true}
      />
    </motion.div>
  );
};

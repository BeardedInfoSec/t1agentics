/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, Plug, Zap, Shield, ArrowRight } from 'lucide-react';
import { usePreferences } from '../../hooks/usePreferences';
import RiggsAvatar from './RiggsAvatar';
import { ROLES, GOALS, STEPS, INTEGRATION_FEATURES, PLAYBOOK_OPTIONS, POPULAR_FEEDS } from './onboardingSteps';
import styles from './OnboardingWizard.module.css';

export default function OnboardingWizard() {
  const { preferences, updatePreferences } = usePreferences();
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [selectedRole, setSelectedRole] = useState(null);
  const [selectedGoals, setSelectedGoals] = useState([]);

  // Don't show if already completed or skipped
  const onboarding = preferences?.onboarding;
  if (onboarding?.completed || onboarding?.skipped) return null;
  if (preferences === null) return null;

  const currentStep = STEPS[step];
  const isLast = step === STEPS.length - 1;
  const username = localStorage.getItem('username') || 'there';

  const finish = useCallback((skipped = false) => {
    updatePreferences({
      onboarding: {
        completed: !skipped,
        skipped,
        current_step: STEPS.length,
        steps_completed: STEPS.map(s => s.id),
        user_role: selectedRole,
        goals: selectedGoals,
      }
    });
  }, [updatePreferences, selectedRole, selectedGoals]);

  const handleNext = useCallback(() => {
    if (isLast) {
      finish(false);
      return;
    }
    setStep(prev => Math.min(prev + 1, STEPS.length - 1));
  }, [isLast, finish]);

  const handleBack = useCallback(() => {
    setStep(prev => Math.max(prev - 1, 0));
  }, []);

  const handleSkip = useCallback(() => {
    finish(true);
  }, [finish]);

  const toggleGoal = useCallback((goalId) => {
    setSelectedGoals(prev =>
      prev.includes(goalId)
        ? prev.filter(g => g !== goalId)
        : [...prev, goalId]
    );
  }, []);

  const navigateTo = useCallback((path) => {
    finish(false);
    navigate(path);
  }, [finish, navigate]);

  // Render step content based on current step
  const renderStepContent = () => {
    switch (currentStep.id) {

      case 'welcome':
        return (
          <div className={styles.stepContent} key="welcome">
            <div className={styles.header}>
              <RiggsAvatar size={56} />
              <h2 className={styles.title}>{currentStep.title}</h2>
            </div>
            <p className={styles.welcomeGreeting}>
              Hey {username}, I am Riggs -- your AI security analyst.
            </p>
            <p className={styles.welcomeSubtext}>
              I will walk you through a quick setup so we can tailor your workspace.
              This only takes a minute, and you can always change things later in Settings.
            </p>
          </div>
        );

      case 'role_select':
        return (
          <div className={styles.stepContent} key="role_select">
            <div className={styles.header}>
              <RiggsAvatar size={40} />
              <h2 className={styles.title}>{currentStep.title}</h2>
            </div>
            <p className={styles.description}>{currentStep.description}</p>
            <div className={styles.selectionGrid}>
              {ROLES.map(role => (
                <button
                  key={role.id}
                  className={`${styles.selectionCard} ${selectedRole === role.id ? styles.selected : ''}`}
                  onClick={() => setSelectedRole(role.id)}
                  type="button"
                >
                  <span className={styles.selectionCardLabel}>
                    {selectedRole === role.id
                      ? <span className={styles.checkIcon}><Check size={12} /></span>
                      : <span className={styles.checkPlaceholder} />
                    }
                    {role.label}
                  </span>
                  <span className={styles.selectionCardDesc}>{role.description}</span>
                </button>
              ))}
            </div>
          </div>
        );

      case 'goals':
        return (
          <div className={styles.stepContent} key="goals">
            <div className={styles.header}>
              <RiggsAvatar size={40} />
              <h2 className={styles.title}>{currentStep.title}</h2>
            </div>
            <p className={styles.description}>{currentStep.description}</p>
            <div className={`${styles.selectionGrid} ${styles.twoCol}`}>
              {GOALS.map(goal => (
                <button
                  key={goal.id}
                  className={`${styles.selectionCard} ${selectedGoals.includes(goal.id) ? styles.selected : ''}`}
                  onClick={() => toggleGoal(goal.id)}
                  type="button"
                >
                  <span className={styles.selectionCardLabel}>
                    {selectedGoals.includes(goal.id)
                      ? <span className={styles.checkIcon}><Check size={12} /></span>
                      : <span className={styles.checkPlaceholder} />
                    }
                    {goal.label}
                  </span>
                  <span className={styles.selectionCardDesc}>{goal.description}</span>
                </button>
              ))}
            </div>
          </div>
        );

      case 'integrations':
        return (
          <div className={styles.stepContent} key="integrations">
            <div className={styles.header}>
              <RiggsAvatar size={40} />
              <h2 className={styles.title}>{currentStep.title}</h2>
            </div>
            <p className={styles.description}>{currentStep.description}</p>
            <div className={styles.selectionGrid}>
              {INTEGRATION_FEATURES.map(feat => (
                <div key={feat.id} className={styles.selectionCard}>
                  <div className={styles.featureRow}>
                    <span className={styles.featureIcon}>
                      <Plug size={16} />
                    </span>
                    <div className={styles.featureInfo}>
                      <span className={styles.selectionCardLabel}>{feat.label}</span>
                      <span className={styles.selectionCardDesc}>{feat.description}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <p className={styles.selectionCardDesc} style={{ marginTop: '0.75rem' }}>
              You can configure integrations anytime from the Connect page.
            </p>
          </div>
        );

      case 'playbooks':
        return (
          <div className={styles.stepContent} key="playbooks">
            <div className={styles.header}>
              <RiggsAvatar size={40} />
              <h2 className={styles.title}>{currentStep.title}</h2>
            </div>
            <p className={styles.description}>{currentStep.description}</p>
            <div className={styles.selectionGrid}>
              {PLAYBOOK_OPTIONS.map(pb => (
                <div key={pb.id} className={styles.selectionCard}>
                  <div className={styles.featureRow}>
                    <span className={styles.featureIcon}>
                      <Zap size={16} />
                    </span>
                    <div className={styles.featureInfo}>
                      <span className={styles.selectionCardLabel}>{pb.label}</span>
                      <span className={styles.selectionCardDesc}>{pb.description}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <p className={styles.selectionCardDesc} style={{ marginTop: '0.75rem' }}>
              Browse 200+ playbooks in the Playbook Marketplace.
            </p>
          </div>
        );

      case 'finish':
        return (
          <div className={`${styles.stepContent} ${styles.finishContent}`} key="finish">
            <RiggsAvatar size={64} />
            <h2 className={styles.title}>{currentStep.title}</h2>
            <p className={styles.description}>{currentStep.description}</p>
            <div className={styles.finishCheckmarks}>
              {selectedRole && (
                <div className={styles.finishItem}>
                  <Check size={16} className={styles.finishItemIcon} />
                  <span>Role: {ROLES.find(r => r.id === selectedRole)?.label || selectedRole}</span>
                </div>
              )}
              {selectedGoals.length > 0 && (
                <div className={styles.finishItem}>
                  <Check size={16} className={styles.finishItemIcon} />
                  <span>{selectedGoals.length} goal{selectedGoals.length !== 1 ? 's' : ''} selected</span>
                </div>
              )}
              <div className={styles.finishItem}>
                <Shield size={16} className={styles.finishItemIcon} />
                <span>Riggs AI assistant is ready to help</span>
              </div>
            </div>
            <div className={styles.quickActions}>
              <button className={styles.quickActionBtn} onClick={() => navigateTo('/queue')} type="button">
                <Shield size={14} /> Security Queue
              </button>
              <button className={styles.quickActionBtn} onClick={() => navigateTo('/connect')} type="button">
                <Plug size={14} /> Connect Tools
              </button>
              <button className={styles.quickActionBtn} onClick={() => navigateTo('/playbooks')} type="button">
                <Zap size={14} /> Playbooks
              </button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className={styles.overlay}>
      <div className={styles.wizard}>
        <div className={styles.content}>
          {renderStepContent()}
        </div>

        {/* Step indicator dots */}
        <div className={styles.stepIndicator}>
          {STEPS.map((s, i) => (
            <span
              key={s.id}
              className={`${styles.dot} ${i === step ? styles.active : ''} ${i < step ? styles.completed : ''}`}
            />
          ))}
        </div>

        {/* Footer navigation */}
        <div className={styles.footer}>
          <div className={styles.footerLeft}>
            {step > 0 && !isLast && (
              <button className={styles.btnSecondary} onClick={handleBack} type="button">
                Back
              </button>
            )}
            <button className={styles.btnSkip} onClick={handleSkip} type="button">
              Skip setup
            </button>
          </div>
          <div className={styles.footerRight}>
            {isLast ? (
              <button className={styles.btnPrimary} onClick={handleNext} type="button">
                Get Started <ArrowRight size={16} />
              </button>
            ) : (
              <button className={styles.btnPrimary} onClick={handleNext} type="button">
                {step === 0 ? "Let's go" : 'Next'} <ArrowRight size={16} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

import { createRouter, createWebHashHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuth } from '../composables/useAuth'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    showChatWidget?: boolean
    requiresAdmin?: boolean
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'home',
    component: () => import('../views/Overview.vue'),
    meta: { title: 'Overview' }
  },
  {
    path: '/hunt',
    name: 'hunt',
    component: () => import('../views/Hunt.vue'),
    props: { category: 'hunt' },
    meta: { title: 'Hunt', showChatWidget: true }
  },
  {
    path: '/alerts',
    name: 'alerts',
    component: () => import('../views/Alerts.vue'),
    meta: { title: 'Alerts', showChatWidget: true }
  },
  {
    path: '/alerts/:ruleId',
    name: 'alert-group-detail',
    component: () => import('../views/AlertGroupDetail.vue'),
    props: true,
    meta: { title: 'Alert Group', showChatWidget: true }
  },
  {
    path: '/alert/:id',
    name: 'alert-detail',
    component: () => import('../views/AlertDetail.vue'),
    props: true,
    meta: { title: 'Alert Detail', showChatWidget: true }
  },
  {
    path: '/dashboards',
    name: 'dashboards',
    component: () => import('../views/Dashboards.vue'),
    meta: { title: 'Dashboards' }
  },
  {
    path: '/grid',
    name: 'grid',
    component: () => import('../components/Grid.vue'),
    meta: { title: 'Grid' }
  },
  {
    path: '/detections',
    name: 'detections',
    component: () => import('../views/Detections.vue'),
    meta: { title: 'Detections', showChatWidget: true }
  },
  {
    path: '/detections/:id',
    name: 'detection-detail',
    component: () => import('../views/DetectionDetail.vue'),
    props: true,
    meta: { title: 'Detection Detail', showChatWidget: true }
  },
  {
    path: '/cases',
    name: 'cases',
    component: () => import('../views/Cases.vue'),
    meta: { title: 'Cases', showChatWidget: true }
  },
  {
    path: '/cases/:id',
    name: 'case-detail',
    component: () => import('../views/CaseDetail.vue'),
    props: true,
    meta: { title: 'Case Detail', showChatWidget: true }
  },
  {
    path: '/playbooks',
    name: 'playbooks',
    component: () => import('../views/Playbooks.vue'),
    meta: { title: 'Playbooks', showChatWidget: true }
  },
  {
    path: '/agents',
    name: 'agents',
    component: () => import('../views/AIAgents.vue'),
    meta: { title: 'AI Agents', requiresAdmin: true }
  },
  {
    path: '/jobs',
    name: 'jobs',
    component: () => import('../views/Jobs.vue'),
    meta: { title: 'PCAP' }
  },
  {
    path: '/jobs/:id',
    name: 'job-detail',
    component: () => import('../views/JobDetail.vue'),
    props: true,
    meta: { title: 'Job Detail' }
  },
  {
    path: '/assistant',
    name: 'assistant',
    component: () => import('../views/Assistant.vue'),
    meta: { title: 'AI Assistant' }
  },
  {
    path: '/admin',
    name: 'admin',
    redirect: '/admin/users',
    meta: { requiresAdmin: true }
  },
  {
    path: '/admin/:tab',
    name: 'administration',
    component: () => import('../views/Administration.vue'),
    props: true,
    meta: { title: 'Administration', requiresAdmin: true }
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/Login.vue'),
    meta: { title: 'Login' }
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/Settings.vue'),
    meta: { title: 'Settings' }
  }
]

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    // If we have a saved position (browser back/forward), use it
    if (savedPosition) {
      return savedPosition
    }
    // Otherwise scroll to top
    return { top: 0 }
  }
})

// Navigation guard for admin routes
router.beforeEach(async (to, from, next) => {
  if (to.meta.requiresAdmin) {
    const { fetchAuth, isUserAdmin } = useAuth()

    // Ensure auth data is loaded
    await fetchAuth()

    if (!isUserAdmin()) {
      // Redirect non-admins to home
      next({ name: 'home' })
      return
    }
  }
  next()
})

// Update document title on navigation
router.afterEach((to) => {
  const title = to.meta.title as string
  document.title = title ? `${title} - Security Onion` : 'Security Onion'
})

export default router

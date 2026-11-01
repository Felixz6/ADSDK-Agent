import { Link } from 'react-router-dom'

const COLUMNS = [
  {
    title: '产品',
    links: [
      { to: '/', label: '产品首页' },
      { to: '/dashboard', label: '概览' },
      { to: '/tasks', label: '任务' },
      { to: '/reports', label: '报告' },
    ],
  },
  {
    title: '分析',
    links: [
      { to: '/analysis/new', label: '新建分析' },
      { to: '/static', label: '静态分析' },
      { to: '/dynamic', label: '动态分析' },
      { to: '/traffic', label: '流量' },
      { to: '/comparisons', label: '版本对比' },
    ],
  },
  {
    title: '系统',
    links: [
      { to: '/environment', label: '环境检测' },
      { to: '/settings', label: '设置' },
    ],
  },
]

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer-inner">
        <div className="footer-grid">
          {COLUMNS.map((column) => (
            <section key={column.title}>
              <h2>{column.title}</h2>
              <ul>
                {column.links.map((link) => (
                  <li key={link.to}>
                    <Link to={link.to}>{link.label}</Link>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <div className="legal">
          <p>AdSDK Agent · 仅用于已获得授权的 APK 测试、隐私审计与合规分析。</p>
          <p>原始敏感标识一律脱敏。未观察到，不等于安全或合规。</p>
        </div>
      </div>
    </footer>
  )
}

export default SiteFooter

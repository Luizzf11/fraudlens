import { useState } from 'react'

const VERDICT_COLOR = {
  malicious: 'text-red-400',
  suspicious: 'text-yellow-400',
  clean: 'text-green-400',
}

function getVerdict(data) {
  if (data.malicious > 0) return 'malicious'
  if (data.suspicious > 0) return 'suspicious'
  return 'clean'
}

function Field({ label, value, mono, accent }) {
  const accentClass =
    accent === 'red' ? 'text-red-400' :
    accent === 'yellow' ? 'text-yellow-400' :
    accent === 'green' ? 'text-green-400' : 'text-white'
  return (
    <div className="bg-gray-900 rounded-lg p-3">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className={`${mono ? 'font-mono text-xs break-all' : 'font-medium'} ${accentClass}`}>{value}</p>
    </div>
  )
}

function ResultCard({ data }) {
  const verdict = getVerdict(data)
  return (
    <div className="mt-8 bg-gray-800 border border-gray-700 rounded-2xl p-6 text-left w-full max-w-xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <span className="text-xs uppercase tracking-widest text-gray-500">Resultado</span>
        <span className={`font-bold uppercase text-sm ${VERDICT_COLOR[verdict]}`}>{verdict}</span>
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <Field label="Tipo" value={data.type?.toUpperCase()} />
        {data.ip && <Field label="IP" value={data.ip} />}
        {data.domain && <Field label="Domínio" value={data.domain} />}
        {data.hash && <Field label="Hash" value={data.hash} mono />}
        {data.country && <Field label="País" value={data.country} />}
        {data.as_owner && <Field label="ASN / Dono" value={`AS${data.asn} · ${data.as_owner}`} />}
        <Field label="Malicioso" value={data.malicious} accent="red" />
        <Field label="Suspeito" value={data.suspicious} accent="yellow" />
        <Field label="Inofensivo" value={data.harmless} accent="green" />
        <Field label="Total engines" value={data.total_engines} />
        {data.reputation !== undefined && <Field label="Reputação VT" value={data.reputation} />}
      </div>

      {data.report && (
        <div className="mt-4 bg-gray-900 rounded-lg p-4">
          <p className="text-xs uppercase tracking-widest text-gray-500 mb-2">Análise IA</p>
          <p className="text-sm text-gray-300 leading-relaxed">{data.report}</p>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [ioc, setIoc] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!ioc.trim()) return
    setLoading(true)
    setResult(null)
    setError(null)
    try {
      const res = await fetch('/ioc/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: ioc.trim() }),
      })
      if (!res.ok) throw new Error(`Erro ${res.status}`)
      setResult(await res.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col items-center px-4 py-16">
      <div className="w-full max-w-xl">
        <div className="mb-10 text-center">
          <h1 className="text-4xl font-bold tracking-tight text-white">
            Fraud<span className="text-blue-400">Lens</span>
          </h1>
          <p className="text-gray-400 mt-2 text-sm">Enriquecimento de IOCs via VirusTotal</p>
        </div>

        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={ioc}
            onChange={e => setIoc(e.target.value)}
            placeholder="IP, domínio ou hash..."
            className="flex-1 bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium px-5 py-3 rounded-xl text-sm transition"
          >
            {loading ? 'Buscando...' : 'Analisar'}
          </button>
        </form>

        {error && <p className="mt-4 text-red-400 text-sm text-center">{error}</p>}
        {result && <ResultCard data={result} />}
      </div>
    </div>
  )
}

import clsx from 'clsx';
import { PolarAngleAxis, RadialBar, RadialBarChart } from 'recharts';

import { clampScore, formatScore, riskColor } from '@/lib/format';

export interface RiskGaugeProps {
  /** Score de risque 0–100 (contrat §3.2). */
  score: number | null | undefined;
  /** Confiance 0–1 de la règle, affichée en sous-titre si fournie. */
  confidence?: number | null;
  size?: number;
  label?: string;
  className?: string;
}

/**
 * Jauge de risque : arc 220°, couleur graduée (vert → cyan → ambre → orange →
 * rose). Le score est borné à 0–100 par `clampScore`.
 */
export function RiskGauge(props: RiskGaugeProps): JSX.Element {
  const { score, confidence, size = 132, label = 'Risque', className } = props;
  const value = clampScore(score);
  const color = riskColor(value);
  const data = [{ name: label, value }];

  return (
    <figure className={clsx('flex flex-col items-center', className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <RadialBarChart
          width={size}
          height={size}
          data={data}
          innerRadius="72%"
          outerRadius="100%"
          startAngle={210}
          endAngle={-30}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar
            dataKey="value"
            angleAxisId={0}
            cornerRadius={6}
            background={{ fill: '#1e293b' }}
            fill={color}
            isAnimationActive={false}
          />
        </RadialBarChart>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-semibold" style={{ color }}>
            {formatScore(score)}
          </span>
          <span className="text-2xs uppercase tracking-wide text-slate-400">{label}</span>
        </div>
      </div>
      {confidence !== null && confidence !== undefined ? (
        <figcaption className="mt-1 text-2xs text-slate-400">
          confiance : {(confidence * 100).toFixed(0)} %
        </figcaption>
      ) : null}
    </figure>
  );
}

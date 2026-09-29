import type { ReactNode } from "react";

interface CardProps {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}

export function Card({ title, action, children }: CardProps) {
  return (
    <section className="adm-card" aria-labelledby={`${slug(title)}-heading`}>
      <div className="adm-card__header">
        <h2 id={`${slug(title)}-heading`} className="adm-card__title">
          {title}
        </h2>
        {action}
      </div>
      <div className="adm-card__body">{children}</div>
    </section>
  );
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

import { useEffect, useState, type FormEvent } from 'react';
import {
  isTriadCaptchaError,
  useTriadCaptcha,
  type AntibotErrorCode,
} from '@triadcaptcha/react';

const SITE_KEY = import.meta.env.VITE_TRIADCAPTCHA_SITE_KEY as string | undefined;

const localizedErrors: Record<AntibotErrorCode, string> = {
  ANTIBOT_CHALLENGE_REQUIRED: 'Требуется фоновая проверка. Повторите отправку.',
  ANTIBOT_RATE_LIMITED: 'Слишком много попыток. Попробуйте позже.',
  ANTIBOT_BLOCKED: 'Запрос временно заблокирован.',
  ANTIBOT_INVALID_PAYLOAD: 'Не удалось подтвердить проверку. Обновите страницу.',
  ANTIBOT_CHALLENGE_EXPIRED: 'Фоновая проверка устарела. Повторите отправку.',
  ANTIBOT_CHALLENGE_REPLAYED: 'Эта проверка уже использована. Повторите отправку.',
  ANTIBOT_SERVICE_UNAVAILABLE: 'Защита временно недоступна. Попробуйте позже.',
  ANTIBOT_CONFIGURATION_ERROR: 'Защита формы настроена неверно.',
};

function cookie(name: string): string {
  const prefix = `${encodeURIComponent(name)}=`;
  const item = document.cookie.split('; ').find((value) => value.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : '';
}

interface DemoFormProps {
  action: 'register' | 'login' | 'lead';
  endpoint: string;
  title: string;
  button: string;
  includePassword?: boolean;
}

function DemoForm({ action, endpoint, title, button, includePassword }: DemoFormProps) {
  const { protectedFetch, interactionProps, isVerifying, resetSignals } = useTriadCaptcha({
    siteKey: SITE_KEY ?? '',
  });
  const [message, setMessage] = useState('');
  const [honeypot, setHoneypot] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage('');
    const form = new FormData(event.currentTarget);
    const body: Record<string, string> = {
      email: String(form.get('email') ?? ''),
    };
    if (includePassword) {
      body.password = String(form.get('password') ?? '');
    }

    try {
      const response = await protectedFetch(
        endpoint,
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': cookie('csrftoken'),
          },
          body: JSON.stringify(body),
        },
        { action, metadata: { honeypot_filled: honeypot.length > 0 } },
      );
      if (!response.ok) {
        setMessage(`HTTP ${response.status}`);
        return;
      }
      setMessage('Запрос разрешён. Бизнес-обработчик выполнен.');
      resetSignals();
    } catch (error) {
      setMessage(
        isTriadCaptchaError(error)
          ? localizedErrors[error.code]
          : 'Не удалось отправить запрос.',
      );
    }
  }

  return (
    <form className="card" onSubmit={submit} {...interactionProps}>
      <h2>{title}</h2>
      <label>
        Email
        <input name="email" type="email" autoComplete="email" required />
      </label>
      {includePassword ? (
        <label>
          Пароль
          <input name="password" type="password" autoComplete="current-password" required />
        </label>
      ) : null}
      <label className="honeypot" aria-hidden="true">
        Company website
        <input
          value={honeypot}
          onChange={(event) => setHoneypot(event.target.value)}
          tabIndex={-1}
          autoComplete="off"
        />
      </label>
      <button disabled={isVerifying} type="submit">
        {isVerifying ? 'Фоновая проверка…' : button}
      </button>
      <output aria-live="polite">{message}</output>
    </form>
  );
}

export function App() {
  const [csrfReady, setCsrfReady] = useState(false);

  useEffect(() => {
    void fetch('/api/csrf/', { credentials: 'same-origin' })
      .then((response) => setCsrfReady(response.ok))
      .catch(() => setCsrfReady(false));
  }, []);

  if (!SITE_KEY) {
    return <main><h1>Не задан VITE_TRIADCAPTCHA_SITE_KEY</h1></main>;
  }

  return (
    <main>
      <header>
        <span className="eyebrow">SELF-HOSTED · SAME-ORIGIN</span>
        <h1>TriadCAPTCHA</h1>
        <p>
          Три обычные формы. При среднем риске proof-of-work выполняется в фоне,
          без изображения, вопроса, чекбокса или внешнего запроса.
        </p>
      </header>
      {!csrfReady ? <p className="notice">Подготавливается CSRF-сессия…</p> : null}
      <section className="grid" aria-busy={!csrfReady}>
        <DemoForm
          action="register"
          endpoint="/api/register/"
          title="Регистрация"
          button="Создать аккаунт"
          includePassword
        />
        <DemoForm
          action="login"
          endpoint="/api/login/"
          title="Вход"
          button="Войти"
          includePassword
        />
        <DemoForm
          action="lead"
          endpoint="/api/lead/"
          title="Заявка"
          button="Отправить заявку"
        />
      </section>
    </main>
  );
}


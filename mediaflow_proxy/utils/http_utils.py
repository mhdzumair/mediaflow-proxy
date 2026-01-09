import * as cheerio from 'cheerio';
import { ContentType } from 'stremio-addon-sdk';
import { Context, CountryCode } from '../types';
import { Source, SourceResult } from './Source';
import { isBlockedDomain } from '../utils';
import { Fetcher, getTmdbId, getTmdbNameAndYear, Id, TmdbId } from '../utils';


interface DooplayerResponse {
  embed_url: string | null;
  type: string | false;
}

interface PlayerOption {
  post: number;
  type: string;
  nume: number;
}

export class AlbKino extends Source {
  public readonly id = 'albkino';
  public readonly label = 'AlbKino';
  public readonly contentTypes: ContentType[] = ['movie'];
  public readonly countryCodes: CountryCode[] = [CountryCode.al];
  public readonly baseUrl = 'https://albkino24.com';

  private readonly fetcher: Fetcher;

  constructor(fetcher: Fetcher) {
    super();
    this.fetcher = fetcher;
  }

  private browserHeaders(referer?: string) {
    return {
      'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36',
      'Accept':
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'X-Requested-With': 'XMLHttpRequest',
      ...(referer ? { Referer: referer } : {}),
    };
  }

  // --- main handler ---
  public async handleInternal(ctx: Context, _type: ContentType, id: Id): Promise<SourceResult[]> {
    const tmdbId = await getTmdbId(ctx, this.fetcher, id);

    // Get main page
    const pageUrl = await this.fetchPageUrl(ctx, tmdbId);
    if (!pageUrl) return [];

    const html = await this.fetcher.text(ctx, pageUrl, { headers: this.browserHeaders(pageUrl.href) });
    const $ = cheerio.load(html);
    const title = $('title').first().text().trim();

    // Extract player options
    const options: PlayerOption[] = $('.dooplay_player_option:not(#player-option-trailer)')
      .map((_i, el) => ({
        post: parseInt($(el).attr('data-post')!),
        type: $(el).attr('data-type')!,
        nume: parseInt($(el).attr('data-nume')!),
      }))
      .get();

    // Fetch all embed URLs in parallel with graceful failure
    const results = await Promise.all(
      options.map((opt) =>
        this.fetchEmbed(ctx, opt, pageUrl, title).catch((err) => {
          console.warn(`AlbKino fetchEmbed failed for post ${opt.post}:`, err);
          return null;
        })
      )
    );

    return results.filter(Boolean) as SourceResult[];
  }

  // --- fetch one embed URL with retry ---
  private async fetchEmbed(
    ctx: Context,
    opt: PlayerOption,
    referer: URL,
    title: string,
    retries = 3
  ): Promise<SourceResult | null> {
    const ajaxUrl = new URL('/wp-admin/admin-ajax.php', this.baseUrl);

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const response = (await this.fetcher.json(ctx, ajaxUrl, {
          method: 'POST',
          headers: {
            ...this.browserHeaders(referer.href),
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          },
          data: new URLSearchParams({
            action: 'doo_player_ajax',
            post: String(opt.post),
            nume: String(opt.nume),
            type: opt.type,
          }).toString(),
        })) as DooplayerResponse;

        if (!response?.embed_url || isBlockedDomain(response.embed_url)) return null;

        return {
          url: new URL(response.embed_url),
          meta: {
            countryCodes: [CountryCode.al],
            referer: referer.href,
            title,
          },
        };
      } catch (err) {
        console.warn(`AlbKino fetchEmbed attempt ${attempt} failed:`, err);
        if (attempt === retries) {
          console.error(`AlbKino fetchEmbed failed after ${retries} attempts for post ${opt.post}`);
          return null;
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    return null;
  }

 private async fetchPageUrl(ctx: Context, tmdbId: TmdbId): Promise<URL | undefined> {
  const [name] = await getTmdbNameAndYear(ctx, this.fetcher, tmdbId); // only name
  const searchUrl = new URL(`/?s=${encodeURIComponent(name)}`, this.baseUrl);
  const html = await this.fetcher.text(ctx, searchUrl, { headers: this.browserHeaders(searchUrl.href) });
  const $ = cheerio.load(html);

  return $('.result-item .title a')
    .map((_i, el) => new URL($(el).attr('href')!, this.baseUrl))
    .get(0);
}

}

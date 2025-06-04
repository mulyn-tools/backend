use anyhow::anyhow;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, routing::get};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::error;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// learned from https://github.com/tokio-rs/axum/blob/main/examples/anyhow-error-response/src/main.rs
pub struct AnyhowError(anyhow::Error);

impl IntoResponse for AnyhowError {
    fn into_response(self) -> Response {
        error!("Returning internal server error for {}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self.0)).into_response()
    }
}

impl<E> From<E> for AnyhowError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // initialize tracing
    let env_log = EnvFilter::try_from_default_env();

    if let Ok(filter) = env_log {
        tracing_subscriber::registry()
            .with(fmt::layer().with_filter(filter))
            .init();
    } else {
        tracing_subscriber::registry().with(fmt::layer()).init();
    }

    let local_url = std::env::var("LOCAL_URL").expect("LOCAL_URL is not set");
    let secret = std::env::var("SECRET").expect("SECRET is not set");
    let password = std::env::var("PASSWORD").expect("PASSWORD is not set");

    let app = Router::new()
        .route("/playlist", get(playlist))
        .route("/edit", post(edit))
        .route("/login", post(login))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods([Method::GET, Method::POST]),
        )
        .with_state((secret, password));
    let listener = tokio::net::TcpListener::bind(local_url).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Deserialize)]
struct PlayListQuery {
    song_name: Option<String>,
    author: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct PlayListEntry {
    name: String,
    author: String,
    note: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    account: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Login {
    data: LoginData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct LoginData {
    account: String,
    token: String,
    avatar: String,
}

async fn login(
    State((_, p)): State<(String, String)>,
    Json(user): Json<User>,
) -> Result<impl IntoResponse, AnyhowError> {
    let User { account, password } = user;

    if account != "root" {
        return Err(anyhow!("User does not exist").into());
    }

    if password != p {
        return Err(anyhow!("User does not exist").into());
    }

    Ok(Json(Login {
        data: LoginData {
            account: "root".to_string(),
            token: "123".to_string(),
            avatar: "".to_string(),
        },
    }))
}

async fn playlist(Query(query): Query<PlayListQuery>) -> Result<impl IntoResponse, AnyhowError> {
    let f = tokio::fs::read_to_string("./playlist.json").await?;
    let db: Vec<PlayListEntry> = serde_json::from_str(&f)?;

    let mut res = vec![];

    let PlayListQuery {
        song_name,
        author,
        note,
    } = query;

    let mut filter_mode = false;

    if let Some(song_name) = song_name {
        let filter = db
            .iter()
            .filter(|e| e.name.contains(&song_name))
            .map(|x| x.to_owned());
        res.extend(filter);
        filter_mode = true;
    }

    if let Some(author) = author {
        let filter = db
            .iter()
            .filter(|e| e.author.contains(&author))
            .map(|x| x.to_owned());
        res.extend(filter);
        filter_mode = true;
    }

    if let Some(note) = note {
        let filter = db
            .iter()
            .filter(|e| e.note.as_ref().is_some_and(|n| n.contains(&note)))
            .map(|x| x.to_owned());

        res.extend(filter);
        filter_mode = true;
    }

    if !filter_mode {
        res = db;
    }

    Ok(Json(res))
}

async fn edit(
    State((secret, _)): State<(String, String)>,
    headers: HeaderMap,
    Json(json): Json<Vec<PlayListEntry>>,
) -> Result<impl IntoResponse, AnyhowError> {
    if headers
        .get("secret")
        .and_then(|s| s.to_str().ok())
        .is_none_or(|sec| sec != secret)
    {
        return Err(anyhow!("SECRET no match").into());
    }

    let f = serde_json::to_string(&json)?;
    tokio::fs::write("./playlist.json", f).await?;

    Ok(())
}

//! Port of `core/internal/congestion/*`.
//!
//! Only **Brutal** is ported — it is Hysteria's signature congestion control.
//! BBR and Reno (`core/internal/congestion/bbr`, plus the `reno`/`bbr` selection
//! in `utils.go`) are not ported: quinn ships its own BBR/Cubic/NewReno, so a
//! port would be redundant. The Go token-bucket pacer
//! (`core/internal/congestion/common/pacer.go`) has no analogue either, because
//! quinn paces internally from [`brutal::BrutalSender`]'s `window()` rather than
//! through a controller-supplied pacer (see `brutal` for the consequences).

pub mod brutal;
